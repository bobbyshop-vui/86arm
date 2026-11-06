// No-UI test of host->guest callbacks: a guest-defined ObjC method that the
// HOST runtime invokes (via performSelector:) must run guest arm64 code.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
static int gHits = 0;
static void hit(id self, SEL _cmd, id arg) { gHits += 10; NSLog(@"guest IMP ran, gHits=%d", gHits); }
int main(void) {
    @autoreleasepool {
        Class cls = objc_allocateClassPair([NSObject class], "CbTest", 0);
        class_addMethod(cls, @selector(hit:), (IMP)hit, "v@:@");
        objc_registerClassPair(cls);
        id o = [[cls alloc] init];
        [o performSelector:@selector(hit:) withObject:nil];
        [o performSelector:@selector(hit:) withObject:nil];
        NSLog(@"back in main, gHits=%d", gHits);
    }
    return 0;
}
