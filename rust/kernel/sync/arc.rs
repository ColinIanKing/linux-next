// SPDX-License-Identifier: GPL-2.0

//! A reference-counted pointer.
//!
//! This module implements a way for users to create reference-counted objects and pointers to
//! them. Such a pointer automatically increments and decrements the count, and drops the
//! underlying object when it reaches zero. It is also safe to use concurrently from multiple
//! threads.
//!
//! It is different from the standard library's [`Arc`] in a few ways:
//! 1. It is backed by the kernel's `refcount_t` type.
//! 2. It does not support weak references, which allows it to be half the size.
//! 3. It saturates the reference count instead of aborting when it goes over a threshold.
//! 4. It does not provide a `get_mut` method, so the ref counted object is pinned.
//! 5. The object in [`Arc`] is pinned implicitly.
//!
//! [`Arc`]: https://doc.rust-lang.org/std/sync/struct.Arc.html

use crate::{
    alloc::{AllocError, Flags, KBox},
    bindings,
    ffi::c_void,
    init::InPlaceInit,
    try_init,
    types::{ForeignOwnable, Opaque},
};
use core::{
    alloc::Layout,
    borrow::{Borrow, BorrowMut},
    fmt,
    marker::PhantomData,
    mem::{ManuallyDrop, MaybeUninit},
    ops::{Deref, DerefMut},
    pin::Pin,
    ptr::NonNull,
};
use pin_init::{self, pin_data, InPlaceWrite, Init, PinInit};

mod std_vendor;

/// A reference-counted pointer to an instance of `T`.
///
/// The reference count is incremented when new instances of [`Arc`] are created, and decremented
/// when they are dropped. When the count reaches zero, the underlying `T` is also dropped.
///
/// # Invariants
///
/// The reference count on an instance of [`Arc`] is always non-zero.
/// The object pointed to by [`Arc`] is always pinned.
///
/// # Examples
///
/// ```
/// use kernel::sync::Arc;
///
/// struct Example {
///     a: u32,
///     b: u32,
/// }
///
/// // Create a refcounted instance of `Example`.
/// let obj = Arc::new(Example { a: 10, b: 20 }, GFP_KERNEL)?;
///
/// // Get a new pointer to `obj` and increment the refcount.
/// let cloned = obj.clone();
///
/// // Assert that both `obj` and `cloned` point to the same underlying object.
/// assert!(core::ptr::eq(&*obj, &*cloned));
///
/// // Destroy `obj` and decrement its refcount.
/// drop(obj);
///
/// // Check that the values are still accessible through `cloned`.
/// assert_eq!(cloned.a, 10);
/// assert_eq!(cloned.b, 20);
///
/// // The refcount drops to zero when `cloned` goes out of scope, and the memory is freed.
/// # Ok::<(), Error>(())
/// ```
///
/// Using `Arc<T>` as the type of `self`:
///
/// ```
/// use kernel::sync::Arc;
///
/// struct Example {
///     a: u32,
///     b: u32,
/// }
///
/// impl Example {
///     fn take_over(self: Arc<Self>) {
///         // ...
///     }
///
///     fn use_reference(self: &Arc<Self>) {
///         // ...
///     }
/// }
///
/// let obj = Arc::new(Example { a: 10, b: 20 }, GFP_KERNEL)?;
/// obj.use_reference();
/// obj.take_over();
/// # Ok::<(), Error>(())
/// ```
///
/// Coercion from `Arc<Example>` to `Arc<dyn MyTrait>`:
///
/// ```
/// use kernel::sync::{Arc, ArcBorrow};
///
/// trait MyTrait {
///     // Trait has a function whose `self` type is `Arc<Self>`.
///     fn example1(self: Arc<Self>) {}
///
///     // Trait has a function whose `self` type is `ArcBorrow<'_, Self>`.
///     fn example2(self: ArcBorrow<'_, Self>) {}
/// }
///
/// struct Example;
/// impl MyTrait for Example {}
///
/// // `obj` has type `Arc<Example>`.
/// let obj: Arc<Example> = Arc::new(Example, GFP_KERNEL)?;
///
/// // `coerced` has type `Arc<dyn MyTrait>`.
/// let coerced: Arc<dyn MyTrait> = obj;
/// # Ok::<(), Error>(())
/// ```
#[repr(transparent)]
#[cfg_attr(CONFIG_RUSTC_HAS_COERCE_POINTEE, derive(core::marker::CoercePointee))]
pub struct Arc<T: ?Sized> {
    ptr: NonNull<ArcInner<T>>,
    // NB: this informs dropck that objects of type `ArcInner<T>` may be used in `<Arc<T> as
    // Drop>::drop`. Note that dropck already assumes that objects of type `T` may be used in
    // `<Arc<T> as Drop>::drop` and the distinction between `T` and `ArcInner<T>` is not presently
    // meaningful with respect to dropck - but this may change in the future so this is left here
    // out of an abundance of caution.
    //
    // See <https://doc.rust-lang.org/nomicon/phantom-data.html#generic-parameters-and-drop-checking>
    // for more detail on the semantics of dropck in the presence of `PhantomData`.
    _p: PhantomData<ArcInner<T>>,
}

#[pin_data]
#[repr(C)]
struct ArcInner<T: ?Sized> {
    refcount: Opaque<bindings::refcount_t>,
    data: T,
}

impl<T: ?Sized> ArcInner<T> {
    /// Converts a pointer to the contents of an [`Arc`] into a pointer to the [`ArcInner`].
    ///
    /// # Safety
    ///
    /// `ptr` must have been returned by a previous call to [`Arc::into_raw`], and the `Arc` must
    /// not yet have been destroyed.
    unsafe fn container_of(ptr: *const T) -> NonNull<ArcInner<T>> {
        let refcount_layout = Layout::new::<bindings::refcount_t>();
        // SAFETY: The caller guarantees that the pointer is valid.
        let val_layout = Layout::for_value(unsafe { &*ptr });
        // SAFETY: We're computing the layout of a real struct that existed when compiling this
        // binary, so its layout is not so large that it can trigger arithmetic overflow.
        let val_offset = unsafe { refcount_layout.extend(val_layout).unwrap_unchecked().1 };

        // Pointer casts leave the metadata unchanged. This is okay because the metadata of `T` and
        // `ArcInner<T>` is the same since `ArcInner` is a struct with `T` as its last field.
        //
        // This is documented at:
        // <https://doc.rust-lang.org/std/ptr/trait.Pointee.html>.
        let ptr = ptr as *const ArcInner<T>;

        // SAFETY: The pointer is in-bounds of an allocation both before and after offsetting the
        // pointer, since it originates from a previous call to `Arc::into_raw` on an `Arc` that is
        // still valid.
        let ptr = unsafe { ptr.byte_sub(val_offset) };

        // SAFETY: The pointer can't be null since you can't have an `ArcInner<T>` value at the null
        // address.
        unsafe { NonNull::new_unchecked(ptr.cast_mut()) }
    }
}

// This is to allow coercion from `Arc<T>` to `Arc<U>` if `T` can be converted to the
// dynamically-sized type (DST) `U`.
#[cfg(not(CONFIG_RUSTC_HAS_COERCE_POINTEE))]
impl<T: ?Sized + core::marker::Unsize<U>, U: ?Sized> core::ops::CoerceUnsized<Arc<U>> for Arc<T> {}

// This is to allow `Arc<U>` to be dispatched on when `Arc<T>` can be coerced into `Arc<U>`.
#[cfg(not(CONFIG_RUSTC_HAS_COERCE_POINTEE))]
impl<T: ?Sized + core::marker::Unsize<U>, U: ?Sized> core::ops::DispatchFromDyn<Arc<U>> for Arc<T> {}

// SAFETY: It is safe to send `Arc<T>` to another thread when the underlying `T` is `Sync` because
// it effectively means sharing `&T` (which is safe because `T` is `Sync`); additionally, it needs
// `T` to be `Send` because any thread that has an `Arc<T>` may ultimately access `T` using a
// mutable reference when the reference count reaches zero and `T` is dropped.
unsafe impl<T: ?Sized + Sync + Send> Send for Arc<T> {}

// SAFETY: It is safe to send `&Arc<T>` to another thread when the underlying `T` is `Sync`
// because it effectively means sharing `&T` (which is safe because `T` is `Sync`); additionally,
// it needs `T` to be `Send` because any thread that has a `&Arc<T>` may clone it and get an
// `Arc<T>` on that thread, so the thread may ultimately access `T` using a mutable reference when
// the reference count reaches zero and `T` is dropped.
unsafe impl<T: ?Sized + Sync + Send> Sync for Arc<T> {}

impl<T> InPlaceInit<T> for Arc<T> {
    type PinnedSelf = Self;

    #[inline]
    fn try_pin_init<E>(init: impl PinInit<T, E>, flags: Flags) -> Result<Self::PinnedSelf, E>
    where
        E: From<AllocError>,
    {
        UniqueArc::try_pin_init(init, flags).map(|u| u.into())
    }

    #[inline]
    fn try_init<E>(init: impl Init<T, E>, flags: Flags) -> Result<Self, E>
    where
        E: From<AllocError>,
    {
        UniqueArc::try_init(init, flags).map(|u| u.into())
    }
}

impl<T> Arc<T> {
    /// Constructs a new reference counted instance of `T`.
    pub fn new(contents: T, flags: Flags) -> Result<Self, AllocError> {
        // INVARIANT: The refcount is initialised to a non-zero value.
        let value = ArcInner {
            // SAFETY: There are no safety requirements for this FFI call.
            refcount: Opaque::new(unsafe { bindings::REFCOUNT_INIT(1) }),
            data: contents,
        };

        let inner = KBox::new(value, flags)?;
        let inner = KBox::leak(inner).into();

        // SAFETY: We just created `inner` with a reference count of 1, which is owned by the new
        // `Arc` object.
        Ok(unsafe { Self::from_inner(inner) })
    }
}

impl<T: ?Sized> Arc<T> {
    /// Constructs a new [`Arc`] from an existing [`ArcInner`].
    ///
    /// # Safety
    ///
    /// The caller must ensure that `inner` points to a valid location and has a non-zero reference
    /// count, one of which will be owned by the new [`Arc`] instance.
    unsafe fn from_inner(inner: NonNull<ArcInner<T>>) -> Self {
        // INVARIANT: By the safety requirements, the invariants hold.
        Arc {
            ptr: inner,
            _p: PhantomData,
        }
    }

    /// Convert the [`Arc`] into a raw pointer.
    ///
    /// The raw pointer has ownership of the refcount that this Arc object owned.
    pub fn into_raw(self) -> *const T {
        let ptr = self.ptr.as_ptr();
        core::mem::forget(self);
        // SAFETY: The pointer is valid.
        unsafe { core::ptr::addr_of!((*ptr).data) }
    }

    /// Return a raw pointer to the data in this arc.
    pub fn as_ptr(this: &Self) -> *const T {
        let ptr = this.ptr.as_ptr();

        // SAFETY: As `ptr` points to a valid allocation of type `ArcInner`,
        // field projection to `data`is within bounds of the allocation.
        unsafe { core::ptr::addr_of!((*ptr).data) }
    }

    /// Recreates an [`Arc`] instance previously deconstructed via [`Arc::into_raw`].
    ///
    /// # Safety
    ///
    /// `ptr` must have been returned by a previous call to [`Arc::into_raw`]. Additionally, it
    /// must not be called more than once for each previous call to [`Arc::into_raw`].
    pub unsafe fn from_raw(ptr: *const T) -> Self {
        // SAFETY: The caller promises that this pointer originates from a call to `into_raw` on an
        // `Arc` that is still valid.
        let ptr = unsafe { ArcInner::container_of(ptr) };

        // SAFETY: By the safety requirements we know that `ptr` came from `Arc::into_raw`, so the
        // reference count held then will be owned by the new `Arc` object.
        unsafe { Self::from_inner(ptr) }
    }

    /// Returns an [`ArcBorrow`] from the given [`Arc`].
    ///
    /// This is useful when the argument of a function call is an [`ArcBorrow`] (e.g., in a method
    /// receiver), but we have an [`Arc`] instead. Getting an [`ArcBorrow`] is free when optimised.
    #[inline]
    pub fn as_arc_borrow(&self) -> ArcBorrow<'_, T> {
        // SAFETY: The constraint that the lifetime of the shared reference must outlive that of
        // the returned `ArcBorrow` ensures that the object remains alive and that no mutable
        // reference can be created.
        unsafe { ArcBorrow::new(self.ptr) }
    }

    /// Compare whether two [`Arc`] pointers reference the same underlying object.
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        core::ptr::eq(this.ptr.as_ptr(), other.ptr.as_ptr())
    }

    /// Converts this [`Arc`] into a [`UniqueArc`], or destroys it if it is not unique.
    ///
    /// When this destroys the `Arc`, it does so while properly avoiding races. This means that
    /// this method will never call the destructor of the value.
    ///
    /// # Examples
    ///
    /// ```
    /// use kernel::sync::{Arc, UniqueArc};
    ///
    /// let arc = Arc::new(42, GFP_KERNEL)?;
    /// let unique_arc = arc.into_unique_or_drop();
    ///
    /// // The above conversion should succeed since refcount of `arc` is 1.
    /// assert!(unique_arc.is_some());
    ///
    /// assert_eq!(*(unique_arc.unwrap()), 42);
    ///
    /// # Ok::<(), Error>(())
    /// ```
    ///
    /// ```
    /// use kernel::sync::{Arc, UniqueArc};
    ///
    /// let arc = Arc::new(42, GFP_KERNEL)?;
    /// let another = arc.clone();
    ///
    /// let unique_arc = arc.into_unique_or_drop();
    ///
    /// // The above conversion should fail since refcount of `arc` is >1.
    /// assert!(unique_arc.is_none());
    ///
    /// # Ok::<(), Error>(())
    /// ```
    pub fn into_unique_or_drop(self) -> Option<Pin<UniqueArc<T>>> {
        // We will manually manage the refcount in this method, so we disable the destructor.
        let me = ManuallyDrop::new(self);
        // SAFETY: We own a refcount, so the pointer is still valid.
        let refcount = unsafe { me.ptr.as_ref() }.refcount.get();

        // If the refcount reaches a non-zero value, then we have destroyed this `Arc` and will
        // return without further touching the `Arc`. If the refcount reaches zero, then there are
        // no other arcs, and we can create a `UniqueArc`.
        //
        // SAFETY: We own a refcount, so the pointer is not dangling.
        let is_zero = unsafe { bindings::refcount_dec_and_test(refcount) };
        if is_zero {
            // SAFETY: We have exclusive access to the arc, so we can perform unsynchronized
            // accesses to the refcount.
            unsafe { core::ptr::write(refcount, bindings::REFCOUNT_INIT(1)) };

            // INVARIANT: We own the only refcount to this arc, so we may create a `UniqueArc`. We
            // must pin the `UniqueArc` because the values was previously in an `Arc`, and they pin
            // their values.
            Some(Pin::from(UniqueArc {
                inner: ManuallyDrop::into_inner(me),
            }))
        } else {
            None
        }
    }
}

// SAFETY: The pointer returned by `into_foreign` comes from a well aligned
// pointer to `ArcInner<T>`.
unsafe impl<T: 'static> ForeignOwnable for Arc<T> {
    const FOREIGN_ALIGN: usize = core::mem::align_of::<ArcInner<T>>();

    type Borrowed<'a> = ArcBorrow<'a, T>;
    type BorrowedMut<'a> = Self::Borrowed<'a>;

    fn into_foreign(self) -> *mut c_void {
        ManuallyDrop::new(self).ptr.as_ptr().cast()
    }

    unsafe fn from_foreign(ptr: *mut c_void) -> Self {
        // SAFETY: The safety requirements of this function ensure that `ptr` comes from a previous
        // call to `Self::into_foreign`.
        let inner = unsafe { NonNull::new_unchecked(ptr.cast::<ArcInner<T>>()) };

        // SAFETY: By the safety requirement of this function, we know that `ptr` came from
        // a previous call to `Arc::into_foreign`, which guarantees that `ptr` is valid and
        // holds a reference count increment that is transferrable to us.
        unsafe { Self::from_inner(inner) }
    }

    unsafe fn borrow<'a>(ptr: *mut c_void) -> ArcBorrow<'a, T> {
        // SAFETY: The safety requirements of this function ensure that `ptr` comes from a previous
        // call to `Self::into_foreign`.
        let inner = unsafe { NonNull::new_unchecked(ptr.cast::<ArcInner<T>>()) };

        // SAFETY: The safety requirements of `from_foreign` ensure that the object remains alive
        // for the lifetime of the returned value.
        unsafe { ArcBorrow::new(inner) }
    }

    unsafe fn borrow_mut<'a>(ptr: *mut c_void) -> ArcBorrow<'a, T> {
        // SAFETY: The safety requirements for `borrow_mut` are a superset of the safety
        // requirements for `borrow`.
        unsafe { <Self as ForeignOwnable>::borrow(ptr) }
    }
}

impl<T: ?Sized> Deref for Arc<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: By the type invariant, there is necessarily a reference to the object, so it is
        // safe to dereference it.
        unsafe { &self.ptr.as_ref().data }
    }
}

impl<T: ?Sized> AsRef<T> for Arc<T> {
    fn as_ref(&self) -> &T {
        self.deref()
    }
}

/// # Examples
///
/// ```
/// # use core::borrow::Borrow;
/// # use kernel::sync::Arc;
/// struct Foo<B: Borrow<u32>>(B);
///
/// // Owned instance.
/// let owned = Foo(1);
///
/// // Shared instance.
/// let arc = Arc::new(1, GFP_KERNEL)?;
/// let shared = Foo(arc.clone());
///
/// let i = 1;
/// // Borrowed from `i`.
/// let borrowed = Foo(&i);
/// # Ok::<(), Error>(())
/// ```
impl<T: ?Sized> Borrow<T> for Arc<T> {
    fn borrow(&self) -> &T {
        self.deref()
    }
}

impl<T: ?Sized> Clone for Arc<T> {
    fn clone(&self) -> Self {
        // SAFETY: By the type invariant, there is necessarily a reference to the object, so it is
        // safe to dereference it.
        let refcount = unsafe { self.ptr.as_ref() }.refcount.get();

        // INVARIANT: C `refcount_inc` saturates the refcount, so it cannot overflow to zero.
        // SAFETY: By the type invariant, there is necessarily a reference to the object, so it is
        // safe to increment the refcount.
        unsafe { bindings::refcount_inc(refcount) };

        // SAFETY: We just incremented the refcount. This increment is now owned by the new `Arc`.
        unsafe { Self::from_inner(self.ptr) }
    }
}

impl<T: ?Sized> Drop for Arc<T> {
    fn drop(&mut self) {
        // SAFETY: By the type invariant, there is necessarily a reference to the object. We cannot
        // touch `refcount` after it's decremented to a non-zero value because another thread/CPU
        // may concurrently decrement it to zero and free it. It is ok to have a raw pointer to
        // freed/invalid memory as long as it is never dereferenced.
        let refcount = unsafe { self.ptr.as_ref() }.refcount.get();

        // INVARIANT: If the refcount reaches zero, there are no other instances of `Arc`, and
        // this instance is being dropped, so the broken invariant is not observable.
        // SAFETY: Also by the type invariant, we are allowed to decrement the refcount.
        let is_zero = unsafe { bindings::refcount_dec_and_test(refcount) };
        if is_zero {
            // The count reached zero, we must free the memory.
            //
            // SAFETY: The pointer was initialised from the result of `KBox::leak`.
            unsafe { drop(KBox::from_raw(self.ptr.as_ptr())) };
        }
    }
}

impl<T: ?Sized> From<UniqueArc<T>> for Arc<T> {
    fn from(item: UniqueArc<T>) -> Self {
        item.inner
    }
}

impl<T: ?Sized> From<Pin<UniqueArc<T>>> for Arc<T> {
    fn from(item: Pin<UniqueArc<T>>) -> Self {
        // SAFETY: The type invariants of `Arc` guarantee that the data is pinned.
        unsafe { Pin::into_inner_unchecked(item).inner }
    }
}

/// A borrowed reference to an [`Arc`] instance.
///
/// For cases when one doesn't ever need to increment the refcount on the allocation, it is simpler
/// to use just `&T`, which we can trivially get from an [`Arc<T>`] instance.
///
/// However, when one may need to increment the refcount, it is preferable to use an `ArcBorrow<T>`
/// over `&Arc<T>` because the latter results in a double-indirection: a pointer (shared reference)
/// to a pointer ([`Arc<T>`]) to the object (`T`). An [`ArcBorrow`] eliminates this double
/// indirection while still allowing one to increment the refcount and getting an [`Arc<T>`] when/if
/// needed.
///
/// # Invariants
///
/// There are no mutable references to the underlying [`Arc`], and it remains valid for the
/// lifetime of the [`ArcBorrow`] instance.
///
/// # Examples
///
/// ```
/// use kernel::sync::{Arc, ArcBorrow};
///
/// struct Example;
///
/// fn do_something(e: ArcBorrow<'_, Example>) -> Arc<Example> {
///     e.into()
/// }
///
/// let obj = Arc::new(Example, GFP_KERNEL)?;
/// let cloned = do_something(obj.as_arc_borrow());
///
/// // Assert that both `obj` and `cloned` point to the same underlying object.
/// assert!(core::ptr::eq(&*obj, &*cloned));
/// # Ok::<(), Error>(())
/// ```
///
/// Using `ArcBorrow<T>` as the type of `self`:
///
/// ```
/// use kernel::sync::{Arc, ArcBorrow};
///
/// struct Example {
///     a: u32,
///     b: u32,
/// }
///
/// impl Example {
///     fn use_reference(self: ArcBorrow<'_, Self>) {
///         // ...
///     }
/// }
///
/// let obj = Arc::new(Example { a: 10, b: 20 }, GFP_KERNEL)?;
/// obj.as_arc_borrow().use_reference();
/// # Ok::<(), Error>(())
/// ```
#[repr(transparent)]
#[cfg_attr(CONFIG_RUSTC_HAS_COERCE_POINTEE, derive(core::marker::CoercePointee))]
pub struct ArcBorrow<'a, T: ?Sized + 'a> {
    inner: NonNull<ArcInner<T>>,
    _p: PhantomData<&'a ()>,
}

// This is to allow `ArcBorrow<U>` to be dispatched on when `ArcBorrow<T>` can be coerced into
// `ArcBorrow<U>`.
#[cfg(not(CONFIG_RUSTC_HAS_COERCE_POINTEE))]
impl<T: ?Sized + core::marker::Unsize<U>, U: ?Sized> core::ops::DispatchFromDyn<ArcBorrow<'_, U>>
    for ArcBorrow<'_, T>
{
}

impl<T: ?Sized> Clone for ArcBorrow<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> Copy for ArcBorrow<'_, T> {}

impl<T: ?Sized> ArcBorrow<'_, T> {
    /// Creates a new [`ArcBorrow`] instance.
    ///
    /// # Safety
    ///
    /// Callers must ensure the following for the lifetime of the returned [`ArcBorrow`] instance:
    /// 1. That `inner` remains valid;
    /// 2. That no mutable references to `inner` are created.
    unsafe fn new(inner: NonNull<ArcInner<T>>) -> Self {
        // INVARIANT: The safety requirements guarantee the invariants.
        Self {
            inner,
            _p: PhantomData,
        }
    }

    /// Creates an [`ArcBorrow`] to an [`Arc`] that has previously been deconstructed with
    /// [`Arc::into_raw`] or [`Arc::as_ptr`].
    ///
    /// # Safety
    ///
    /// * The provided pointer must originate from a call to [`Arc::into_raw`] or [`Arc::as_ptr`].
    /// * For the duration of the lifetime annotated on this `ArcBorrow`, the reference count must
    ///   not hit zero.
    /// * For the duration of the lifetime annotated on this `ArcBorrow`, there must not be a
    ///   [`UniqueArc`] reference to this value.
    pub unsafe fn from_raw(ptr: *const T) -> Self {
        // SAFETY: The caller promises that this pointer originates from a call to `into_raw` on an
        // `Arc` that is still valid.
        let ptr = unsafe { ArcInner::container_of(ptr) };

        // SAFETY: The caller promises that the value remains valid since the reference count must
        // not hit zero, and no mutable reference will be created since that would involve a
        // `UniqueArc`.
        unsafe { Self::new(ptr) }
    }
}

impl<T: ?Sized> From<ArcBorrow<'_, T>> for Arc<T> {
    fn from(b: ArcBorrow<'_, T>) -> Self {
        // SAFETY: The existence of `b` guarantees that the refcount is non-zero. `ManuallyDrop`
        // guarantees that `drop` isn't called, so it's ok that the temporary `Arc` doesn't own the
        // increment.
        ManuallyDrop::new(unsafe { Arc::from_inner(b.inner) })
            .deref()
            .clone()
    }
}

impl<T: ?Sized> Deref for ArcBorrow<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: By the type invariant, the underlying object is still alive with no mutable
        // references to it, so it is safe to create a shared reference.
        unsafe { &self.inner.as_ref().data }
    }
}

/// A refcounted object that is known to have a refcount of 1.
///
/// It is mutable and can be converted to an [`Arc`] so that it can be shared.
///
/// # Invariants
///
/// `inner` always has a reference count of 1.
///
/// # Examples
///
/// In the following example, we make changes to the inner object before turning it into an
/// `Arc<Test>` object (after which point, it cannot be mutated directly). Note that `x.into()`
/// cannot fail.
///
/// ```
/// use kernel::sync::{Arc, UniqueArc};
///
/// struct Example {
///     a: u32,
///     b: u32,
/// }
///
/// fn test() -> Result<Arc<Example>> {
///     let mut x = UniqueArc::new(Example { a: 10, b: 20 }, GFP_KERNEL)?;
///     x.a += 1;
///     x.b += 1;
///     Ok(x.into())
/// }
///
/// # test().unwrap();
/// ```
///
/// In the following example we first allocate memory for a refcounted `Example` but we don't
/// initialise it on allocation. We do initialise it later with a call to [`UniqueArc::write`],
/// followed by a conversion to `Arc<Example>`. This is particularly useful when allocation happens
/// in one context (e.g., sleepable) and initialisation in another (e.g., atomic):
///
/// ```
/// use kernel::sync::{Arc, UniqueArc};
///
/// struct Example {
///     a: u32,
///     b: u32,
/// }
///
/// fn test() -> Result<Arc<Example>> {
///     let x = UniqueArc::new_uninit(GFP_KERNEL)?;
///     Ok(x.write(Example { a: 10, b: 20 }).into())
/// }
///
/// # test().unwrap();
/// ```
///
/// In the last example below, the caller gets a pinned instance of `Example` while converting to
/// `Arc<Example>`; this is useful in scenarios where one needs a pinned reference during
/// initialisation, for example, when initialising fields that are wrapped in locks.
///
/// ```
/// use kernel::sync::{Arc, UniqueArc};
///
/// struct Example {
///     a: u32,
///     b: u32,
/// }
///
/// fn test() -> Result<Arc<Example>> {
///     let mut pinned = Pin::from(UniqueArc::new(Example { a: 10, b: 20 }, GFP_KERNEL)?);
///     // We can modify `pinned` because it is `Unpin`.
///     pinned.as_mut().a += 1;
///     Ok(pinned.into())
/// }
///
/// # test().unwrap();
/// ```
pub struct UniqueArc<T: ?Sized> {
    inner: Arc<T>,
}

impl<T> InPlaceInit<T> for UniqueArc<T> {
    type PinnedSelf = Pin<Self>;

    #[inline]
    fn try_pin_init<E>(init: impl PinInit<T, E>, flags: Flags) -> Result<Self::PinnedSelf, E>
    where
        E: From<AllocError>,
    {
        UniqueArc::new_uninit(flags)?.write_pin_init(init)
    }

    #[inline]
    fn try_init<E>(init: impl Init<T, E>, flags: Flags) -> Result<Self, E>
    where
        E: From<AllocError>,
    {
        UniqueArc::new_uninit(flags)?.write_init(init)
    }
}

impl<T> InPlaceWrite<T> for UniqueArc<MaybeUninit<T>> {
    type Initialized = UniqueArc<T>;

    fn write_init<E>(mut self, init: impl Init<T, E>) -> Result<Self::Initialized, E> {
        let slot = self.as_mut_ptr();
        // SAFETY: When init errors/panics, slot will get deallocated but not dropped,
        // slot is valid.
        unsafe { init.__init(slot)? };
        // SAFETY: All fields have been initialized.
        Ok(unsafe { self.assume_init() })
    }

    fn write_pin_init<E>(mut self, init: impl PinInit<T, E>) -> Result<Pin<Self::Initialized>, E> {
        let slot = self.as_mut_ptr();
        // SAFETY: When init errors/panics, slot will get deallocated but not dropped,
        // slot is valid and will not be moved, because we pin it later.
        unsafe { init.__pinned_init(slot)? };
        // SAFETY: All fields have been initialized.
        Ok(unsafe { self.assume_init() }.into())
    }
}

impl<T> UniqueArc<T> {
    /// Tries to allocate a new [`UniqueArc`] instance.
    pub fn new(value: T, flags: Flags) -> Result<Self, AllocError> {
        Ok(Self {
            // INVARIANT: The newly-created object has a refcount of 1.
            inner: Arc::new(value, flags)?,
        })
    }

    /// Tries to allocate a new [`UniqueArc`] instance whose contents are not initialised yet.
    pub fn new_uninit(flags: Flags) -> Result<UniqueArc<MaybeUninit<T>>, AllocError> {
        // INVARIANT: The refcount is initialised to a non-zero value.
        let inner = KBox::try_init::<AllocError>(
            try_init!(ArcInner {
                // SAFETY: There are no safety requirements for this FFI call.
                refcount: Opaque::new(unsafe { bindings::REFCOUNT_INIT(1) }),
                data <- pin_init::uninit::<T, AllocError>(),
            }? AllocError),
            flags,
        )?;
        Ok(UniqueArc {
            // INVARIANT: The newly-created object has a refcount of 1.
            // SAFETY: The pointer from the `KBox` is valid.
            inner: unsafe { Arc::from_inner(KBox::leak(inner).into()) },
        })
    }
}

impl<T> UniqueArc<MaybeUninit<T>> {
    /// Converts a `UniqueArc<MaybeUninit<T>>` into a `UniqueArc<T>` by writing a value into it.
    pub fn write(mut self, value: T) -> UniqueArc<T> {
        self.deref_mut().write(value);
        // SAFETY: We just wrote the value to be initialized.
        unsafe { self.assume_init() }
    }

    /// Unsafely assume that `self` is initialized.
    ///
    /// # Safety
    ///
    /// The caller guarantees that the value behind this pointer has been initialized. It is
    /// *immediate* UB to call this when the value is not initialized.
    pub unsafe fn assume_init(self) -> UniqueArc<T> {
        let inner = ManuallyDrop::new(self).inner.ptr;
        UniqueArc {
            // SAFETY: The new `Arc` is taking over `ptr` from `self.inner` (which won't be
            // dropped). The types are compatible because `MaybeUninit<T>` is compatible with `T`.
            inner: unsafe { Arc::from_inner(inner.cast()) },
        }
    }

    /// Initialize `self` using the given initializer.
    pub fn init_with<E>(mut self, init: impl Init<T, E>) -> core::result::Result<UniqueArc<T>, E> {
        // SAFETY: The supplied pointer is valid for initialization.
        match unsafe { init.__init(self.as_mut_ptr()) } {
            // SAFETY: Initialization completed successfully.
            Ok(()) => Ok(unsafe { self.assume_init() }),
            Err(err) => Err(err),
        }
    }

    /// Pin-initialize `self` using the given pin-initializer.
    pub fn pin_init_with<E>(
        mut self,
        init: impl PinInit<T, E>,
    ) -> core::result::Result<Pin<UniqueArc<T>>, E> {
        // SAFETY: The supplied pointer is valid for initialization and we will later pin the value
        // to ensure it does not move.
        match unsafe { init.__pinned_init(self.as_mut_ptr()) } {
            // SAFETY: Initialization completed successfully.
            Ok(()) => Ok(unsafe { self.assume_init() }.into()),
            Err(err) => Err(err),
        }
    }
}

impl<T: ?Sized> From<UniqueArc<T>> for Pin<UniqueArc<T>> {
    fn from(obj: UniqueArc<T>) -> Self {
        // SAFETY: It is not possible to move/replace `T` inside a `Pin<UniqueArc<T>>` (unless `T`
        // is `Unpin`), so it is ok to convert it to `Pin<UniqueArc<T>>`.
        unsafe { Pin::new_unchecked(obj) }
    }
}

impl<T: ?Sized> Deref for UniqueArc<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<T: ?Sized> DerefMut for UniqueArc<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: By the `Arc` type invariant, there is necessarily a reference to the object, so
        // it is safe to dereference it. Additionally, we know there is only one reference when
        // it's inside a `UniqueArc`, so it is safe to get a mutable reference.
        unsafe { &mut self.inner.ptr.as_mut().data }
    }
}

/// # Examples
///
/// ```
/// # use core::borrow::Borrow;
/// # use kernel::sync::UniqueArc;
/// struct Foo<B: Borrow<u32>>(B);
///
/// // Owned instance.
/// let owned = Foo(1);
///
/// // Owned instance using `UniqueArc`.
/// let arc = UniqueArc::new(1, GFP_KERNEL)?;
/// let shared = Foo(arc);
///
/// let i = 1;
/// // Borrowed from `i`.
/// let borrowed = Foo(&i);
/// # Ok::<(), Error>(())
/// ```
impl<T: ?Sized> Borrow<T> for UniqueArc<T> {
    fn borrow(&self) -> &T {
        self.deref()
    }
}

/// # Examples
///
/// ```
/// # use core::borrow::BorrowMut;
/// # use kernel::sync::UniqueArc;
/// struct Foo<B: BorrowMut<u32>>(B);
///
/// // Owned instance.
/// let owned = Foo(1);
///
/// // Owned instance using `UniqueArc`.
/// let arc = UniqueArc::new(1, GFP_KERNEL)?;
/// let shared = Foo(arc);
///
/// let mut i = 1;
/// // Borrowed from `i`.
/// let borrowed = Foo(&mut i);
/// # Ok::<(), Error>(())
/// ```
impl<T: ?Sized> BorrowMut<T> for UniqueArc<T> {
    fn borrow_mut(&mut self) -> &mut T {
        self.deref_mut()
    }
}

impl<T: fmt::Display + ?Sized> fmt::Display for UniqueArc<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.deref(), f)
    }
}

impl<T: fmt::Display + ?Sized> fmt::Display for Arc<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.deref(), f)
    }
}

impl<T: fmt::Debug + ?Sized> fmt::Debug for UniqueArc<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.deref(), f)
    }
}

impl<T: fmt::Debug + ?Sized> fmt::Debug for Arc<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.deref(), f)
    }
}
