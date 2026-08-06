// test_float.m — stress-tests the NEW float/double support:
//   - [NSNumber numberWithDouble:3.5]  : class method with a DOUBLE
//                                         ARGUMENT (never tested before —
//                                         needs the D0-D7 FP register bank)
//   - [n doubleValue]                  : instance method with a DOUBLE
//                                         RETURN (same D0-D7 requirement,
//                                         return side)

#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSNumber *n = [NSNumber numberWithDouble:3.5];
        double v = [n doubleValue];
        NSLog(@"%f", v);
    }
    return 0;
}