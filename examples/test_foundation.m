// test_foundation.m — a minimal Objective-C file that links real Foundation,
// used only to test `86arm --deps` (reading the chained-fixups bind table).
// This is NOT expected to run under 86arm yet — it needs dyld + the real
// Objective-C runtime, neither of which 86arm emulates. It's purely a
// binary sample with real LC_LOAD_DYLIB / LC_DYLD_CHAINED_FIXUPS data.

#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *s = [NSString stringWithUTF8String:"hello from Foundation"];
        NSLog(@"%@", s);
    }
    return 0;
}