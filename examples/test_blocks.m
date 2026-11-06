// Blocks, libdispatch, NSTimer, printf/NSString formatting, libc on guest
// memory: everything a "real" app needs beyond a bare window.
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <Block.h>

static int gTicks = 0;

int main(void) {
    @autoreleasepool {
        // --- libc on guest memory ---
        char *buf = malloc(64);
        strcpy(buf, "guest heap works");
        printf("printf: %s | len=%d | %5.2f | 0x%x | %ld\n", buf, (int)strlen(buf), 3.14159, 255, 1234567890123L);
        char tmp[48];
        snprintf(tmp, sizeof tmp, "snprintf %d+%d=%d", 20, 22, 42);
        puts(tmp);
        printf("sqrt(2)=%.6f pow(2,10)=%.0f sin(0)=%.1f\n", sqrt(2.0), pow(2.0, 10.0), sin(0.0));
        free(buf);

        // --- NSString formatting (variadic ObjC) ---
        NSString *s = [NSString stringWithFormat:@"%@ has %d items, avg %.1f (%s)", @"list", 3, 2.5, "ok"];
        NSLog(@"formatted: %@", s);

        // --- non-capturing (global) block as a comparator argument ---
        NSArray *arr = @[@"pear", @"apple", @"fig"];
        NSArray *sorted = [arr sortedArrayUsingComparator:^NSComparisonResult(id a, id b) {
            return [(NSString *)a compare:(NSString *)b];
        }];
        NSLog(@"sorted: %@", sorted);

        // --- capturing block, copied, run later via dispatch_async ---
        __block int total = 0;
        int base = 100;
        dispatch_block_t blk = Block_copy(^{ total += base + 1; NSLog(@"async block ran, total=%d", total); });
        dispatch_async(dispatch_get_main_queue(), blk);

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), Block_copy(^{ NSLog(@"dispatch_after fired"); }));

        // --- repeating NSTimer with a block (timer is the block's argument) ---
        [NSTimer scheduledTimerWithTimeInterval:0.1 repeats:YES block:Block_copy(^(NSTimer *t) {
            gTicks++;
            NSLog(@"tick %d", gTicks);
            if (gTicks == 3) [t invalidate];
        })];

        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.8]];
        NSLog(@"done: total=%d ticks=%d", total, gTicks);
    }
    return 0;
}
