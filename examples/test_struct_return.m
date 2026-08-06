// test_struct_return.m — stress-tests the NEW struct-return generic path:
// NSRange is `{_NSRange="location"Q"length"Q}` — a 16-byte struct made
// entirely of NSUInteger (no float/double fields), which is exactly the
// case objc_ffi.nim's new struct-return support targets (≤16 bytes,
// no float, returned packed into X0/X1 per AAPCS64).

#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *haystack = [NSString stringWithUTF8String:"hello world"];
        NSString *needle = [NSString stringWithUTF8String:"world"];

        NSRange r = [haystack rangeOfString:needle];

        NSLog(@"%lu", (unsigned long)r.location);
        NSLog(@"%lu", (unsigned long)r.length);
    }
    return 0;
}