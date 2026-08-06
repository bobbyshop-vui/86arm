// test_nsarray.m — stress-tests parts of the generic objc_msgSend path
// that test_foundation.m never exercised:
//   - [NSMutableArray array]      : 0-arg CLASS method (like `new`, but a
//                                    different class/selector combo)
//   - [arr addObject:obj]         : 1-arg method with VOID return (never
//                                    tested before — only object returns
//                                    were exercised so far)
//   - [arr count]                 : 0-arg method with INTEGER return
//                                    (NSUInteger, 'Q' encoding — never
//                                    tested before, only object returns)
//   - [arr objectAtIndex:i]       : 1-arg method with an INTEGER argument
//                                    (never tested before — only object/
//                                    char* arguments were exercised)
//   - NSLog(@"%lu", ...)          : integer vararg through the same
//                                    single-vararg-on-stack path already
//                                    proven for %@ — should work
//                                    bit-for-bit identically since both
//                                    are just 8-byte stack slots, but
//                                    genuinely untested until now.

#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSMutableArray *arr = [NSMutableArray array];
        [arr addObject:[NSString stringWithUTF8String:"alpha"]];
        [arr addObject:[NSString stringWithUTF8String:"beta"]];
        [arr addObject:[NSString stringWithUTF8String:"gamma"]];

        NSUInteger n = [arr count];
        NSLog(@"%lu", (unsigned long)n);

        NSString *first = [arr objectAtIndex:0];
        NSLog(@"%@", first);

        NSString *last = [arr objectAtIndex:2];
        NSLog(@"%@", last);
    }
    return 0;
}