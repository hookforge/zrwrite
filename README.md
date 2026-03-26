# ZRWRITE
## YinMo19

> What is this?
>
> It is a framework for patching AArch64 binaries on macOS and Linux. Android and iOS support is currently under development.

So, what can you do with this library? Imagine you have a binary—whether it is stripped or not, optimized or not—you can simply use this library to hook it.

### What can we do and what we have done?
zrwrite supports both function entry detours and instrumentation of almost any opcode.

Function Detours: If the original function contains more than 4 opcodes, detouring is straightforward; otherwise, it becomes more challenging.

Instruction Instrumentation: This is the most complex part of development. You must consider several edge cases:

- What if you select a point that uses a PC-relative opcode?
- What if a branch target falls within the patched opcodes' window?
- What if you want to write TLS (Thread Local Storage) code in your patch? (Note: This is not yet supported).

We have already solved the most difficult technical hurdles. For you, the user, you only need to focus on writing your patch code and selecting the specific hook point. (If you ensure it is our wrong, please report an issue to us, we will fix it as soon as possible.)

### How to use that?
Thanks to Zig, you can write your patch code in either Zig or C. While C support is provided, we recommend using Zig because it is more powerful and easier to write for this purpose.

We have introduced that our libirary supports replace function and instruction, so you should decide which to use. If you want to change a function with a totally different way or just force a function to return a simple value., you can choose replace mode, other case like a very very large function (automatically inlined by compiler) you want to make some log or just make a register some change, instuction is what you want.

And out libirary is used in 3 steps. 
1. write patch code and build into a o file, 
2. pack o file with a metadata json, 
3. patch the original binary.

A metadata json is like this:
```json
{
  "target": {
    "arch": "aarch64",
    "os": "macos",
    "binary_format": "macho"
  },
  "payload": {
    "object_path": "payload_tokio_trace.o",
    "object_format": "macho"
  },
  "hooks": [
    {
      "kind": "instrument",
      "target": {
        "kind": "virtual_address",
        "virtual_address": "0x1000038bc"
      },
      "expected_bytes": "4810001208150011",
      "handler_symbol": "on_tokio_mix"
    }
  ]
}
```
The metadata does NOT specify which binary you are patching. It only defines how and where to patch using specific handlers.

When writing patch code, you must match the ABI of the specific language (e.g., Objective-C's `objc_msgSend` or C++'s `std::vector`). Our library does not guarantee ABI correctness; you are responsible for ensuring the signatures match.

### Replaced mode
Suppose you want to intercept an HTTP request to httpbin and modify the output in Objective-C. You might have code like this:
```objc
#import <Foundation/Foundation.h>

@interface ArHttpClient : NSObject {
    NSString *_lastBody;
}
- (const char *)fetchBodyCString;
@end

@implementation ArHttpClient

- (const char *)fetchBodyCString {
    NSURL *url = [NSURL URLWithString:@"https://httpbin.org/get"];
    NSError *error = nil;
    NSString *body = [NSString stringWithContentsOfURL:url
                                              encoding:NSUTF8StringEncoding
                                                 error:&error];
    if (body == nil) {
        body = [NSString stringWithFormat:@"request failed: %@", error.localizedDescription];
    }

    // Keep the fetched string alive after this method returns so the returned
    // UTF-8 pointer remains valid for the immediate `puts()` call in `main`.
    _lastBody = body;
    return _lastBody.UTF8String;
}

@end

int main(void) {
    @autoreleasepool {
        ArHttpClient *client = [[ArHttpClient alloc] init];
        puts([client fetchBodyCString]);
    }
    return 0;
}
```
So build with commands like
```sh
xcrun --sdk macosx clang -arch arm64 -O2 -g -fobjc-arc main.m -framework Foundation -o objc_httpbin_demo
```
To replace the response with your own string, you can write the following in Zig:
```zig
const hooked = "[artest] hooked.";

/// Zig replacement function that matches the Objective-C IMP calling shape for:
/// `- (const char *)fetchBodyCString`.
///
/// From the patcher's point of view this is just an AArch64 C ABI function:
/// - x0 = self
/// - x1 = _cmd
/// - x0 return value = replacement `const char *`
export fn replacement_fetchBodyCString(self: ?*anyopaque, cmd: ?*anyopaque) callconv(.c) [*:0]const u8 {
    _ = self;
    _ = cmd;
    return hooked.ptr;
}
```
yeah, you should keep the abi for function calling, using ida to know what should you write to match the original function's signature.

To patch the binary, you should build an O file and write a meta json like
```json
// replace.meta.json
{
  "target": {
    "arch": "aarch64",
    "os": "macos",
    "binary_format": "macho"
  },
  "payload_object_path": "payload_replace.o",
  "payload_object_format": "macho",
  "hooks": [
    {
      "kind": "replace",
      "target": {
        "kind": "symbol",
        "symbol": "-[ArHttpClient fetchBodyCString]" // in original binary, what you inspect just now.
      },
      "handler_symbol": "replacement_fetchBodyCString" // defined in your zig code
    }
  ]
}
```
And 
```sh
zig build-obj -target aarch64-macos -O ReleaseSmall -fstrip \
  -Mroot=payload_replace.zig \
  -femit-bin=payload_replace_zig.o
```
So far, the first step is done.

We recommend you to inspect the binary with 
```sh
zrwrite inspect \
  --input objc_httpbin_demo \
  --symbol '-[ArHttpClient fetchBodyCString]'
```
to make sure the symbol is exists. After prepatch check, generate a zrpb bundle file with 
```sh 
zrwrite bundle --output zig_replace.zrpb --meta replace.meta.json
```
Or without the metadata, just using cli params is accepted.
```sh
zrwrite bundle \
  --output zig_replace.zrpb \
  --payload payload_replace_zig.o \
  --handler-symbol replacement_fetchBodyCString \
  --hook-kind replace \
  --target-symbol '-[ArHttpClient fetchBodyCString]' \
  --target-os macos \
  --target-format macho \
  --target-arch aarch64 \
  --payload-format macho
```

The last one is 
```sh 
zrwrite apply --bundle zig_instrument.zrpb --input objc_httpbin_demo --output objc_httpbin_demo_patched
```
apply the zrpb bundle for binary input and generate a new file. On macos, you should codesign a ad-hoc sign, else you will get a "operation not permitted" error when execute the patched binary.
```sh
codesign -f -s - objc_httpbin_demo_patched
./objc_httpbin_demo_patched
# output is `[artest] hooked.`
```

### instruction mode
Instrument mode allows you to inject logic (like logging) at a specific offset. To achieve the same result as the example above using instrumentation:
```zig
const zrwrite = @import("zrwrite");

const hooked = "[artest] hooked.";

/// Early-return the Objective-C method by editing machine state only.
///
/// We intentionally keep this payload at the register/PC layer:
/// - x0 = `self`
/// - x1 = `_cmd`
/// - x30 = caller return address
///
/// Returning a `const char *` from an ObjC method is therefore just:
/// 1. place the replacement pointer into x0
/// 2. branch directly to the caller by setting `pc = x30`
export fn on_hit(address: u64, ctx: *zrwrite.HookContext) callconv(.c) void {
    _ = address;

    // Touch the canonical Objective-C argument registers explicitly so the
    // fixture documents which architectural values the payload is relying on.
    _ = ctx.regs.named.x0; // self
    _ = ctx.regs.named.x1; // _cmd / selector

    ctx.regs.named.x0 = @intFromPtr(hooked.ptr);
    ctx.pc = ctx.regs.named.x30;
}
```
after build, using 
```sh
zrwrite bundle \
  --output zig_instrument.zrpb \
  --payload payload_instrument.o \
  --handler-symbol on_hit \
  --target-symbol '-[ArHttpClient fetchBodyCString]' \
  --target-os macos \
  --target-format macho \
  --target-arch aarch64 \
  --payload-format macho
```
and same with before. If you just want to hack in a file offset, write json like
```json
{
  "target": {
    "arch": "aarch64",
    "os": "macos",
    "binary_format": "macho"
  },
  "payload": {
    "object_path": "payload_instrument.o",
    "object_format": "macho"
  },
  "hooks": [
    {
      "kind": "instrument",
      "target": {
        "kind": "virtual_address",
        "virtual_address": "0x100000d50" // you should determine the offset in ida.
      },
      // Why use expected_bytes? Compilers don't guarantee 
      // the same output every time. expected_bytes acts as 
      // a safety check to ensure you are patching the correct instructions. 
      // 
      // If the binary changes, zrwrite will catch the mismatch. 
      // You can use zrwrite inspect to verify the bytes
      // at a specific offset before patching.
      "expected_bytes": "680a00f9", 
      "handler_symbol": "on_hit"
    }
  ]
}
```
