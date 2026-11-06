// AppKit demo: an ARM64 Cocoa app driven by 86arm on an x86 Mac.
// Window + menu bar (Cmd+Q) + label + a REAL clickable button + a block timer. The click
// handler is an arm64 function registered with the plain ObjC runtime API;
// 86arm re-enters the emulator whenever AppKit (native, x86) calls it.
#import <Cocoa/Cocoa.h>
#import <objc/runtime.h>
#include <Block.h>

static NSTextField *gLabel;
static int gCount = 0;

static NSTextField *gClock;
static int gSecs = 0;

static void onClick(id self, SEL _cmd, id sender) {
    gCount++;
    [gLabel setStringValue:[NSString stringWithFormat:@"Clicked %d time(s) - from ARM64 on x86!", gCount]];
}

int main(void) {
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

        NSMenu *bar = [[NSMenu alloc] init];
        NSMenuItem *appItem = [[NSMenuItem alloc] init];
        [bar addItem:appItem];
        NSMenu *appMenu = [[NSMenu alloc] init];
        [appMenu addItemWithTitle:@"Quit 86arm demo" action:@selector(terminate:) keyEquivalent:@"q"];
        [appItem setSubmenu:appMenu];
        [NSApp setMainMenu:bar];

        // A class defined at runtime whose method is the arm64 function above.
        Class cls = objc_allocateClassPair([NSObject class], "ArmHandler", 0);
        class_addMethod(cls, @selector(clicked:), (IMP)onClick, "v@:@");
        objc_registerClassPair(cls);
        id handler = [[cls alloc] init];

        NSWindow *w = [[NSWindow alloc] initWithContentRect:NSMakeRect(200,200,480,300)
            styleMask:(NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskResizable|NSWindowStyleMaskMiniaturizable)
            backing:NSBackingStoreBuffered defer:NO];
        [w setTitle:@"86arm: arm64 app on x86 Mac"];

        gLabel = [NSTextField labelWithString:@"Hello from an ARM64 binary running on x86!"];
        [gLabel setFrame:NSMakeRect(40, 190, 400, 30)];
        [[w contentView] addSubview:gLabel];

        NSButton *btn = [NSButton buttonWithTitle:@"Click me" target:handler action:@selector(clicked:)];
        [btn setFrame:NSMakeRect(170, 110, 140, 40)];
        [[w contentView] addSubview:btn];

        gClock = [NSTextField labelWithString:@"Running for 0 s"];
        [gClock setFrame:NSMakeRect(40, 60, 400, 24)];
        [[w contentView] addSubview:gClock];
        // A repeating NSTimer whose callback is an arm64 BLOCK.
        [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:Block_copy(^(NSTimer *t) {
            gSecs++;
            [gClock setStringValue:[NSString stringWithFormat:@"Running for %d s (timer block, arm64)", gSecs]];
        })];

        [w makeKeyAndOrderFront:nil];
        [NSApp activateIgnoringOtherApps:YES];
        [NSApp run];
    }
    return 0;
}
