// IrisLite - ObjC runtime hooks (public Apple APIs only, version-proof)
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreLocation/CoreLocation.h>
#import <objc/runtime.h>

static NSString *const kShotNote = @"UIApplicationUserDidTakeScreenshotNotification";

// ---------- saved IMPs ----------
static void (*orig_post3)(id, SEL, id, id, id) = 0;
static void (*orig_post1)(id, SEL, id) = 0;
static BOOL (*orig_isCaptured)(id, SEL) = 0;
static BOOL (*orig_captured)(id, SEL) = 0;
static id (*orig_clLocation)(id, SEL) = 0;

// ---------- ghost-location config (cached at load) ----------
static BOOL g_ghost = NO;
static double g_lat = 0, g_lon = 0;

static void iris_read_config(void) {
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/IrisLite.plist"];
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:p];
    if (!d) return;
    if ([[d objectForKey:@"GhostLocation"] boolValue]) {
        g_ghost = YES;
        g_lat = [[d objectForKey:@"Lat"] doubleValue];
        g_lon = [[d objectForKey:@"Lon"] doubleValue];
    }
}

// ---------- replacements ----------
static void hook_post3(id self, SEL sel, id name, id obj, id info) {
    if ([name isKindOfClass:[NSString class]] && [name isEqualToString:kShotNote]) {
        return; // screenshot happens, nobody is told
    }
    orig_post3(self, sel, name, obj, info);
}

static void hook_post1(id self, SEL sel, id note) {
    if ([note isKindOfClass:[NSNotification class]] &&
        [[[note name] description] isEqualToString:kShotNote]) {
        return;
    }
    orig_post1(self, sel, note);
}

static BOOL hook_isCaptured(id self, SEL sel) {
    (void)self; (void)sel;
    return NO; // never recording, as far as anyone in here knows
}

static BOOL hook_captured(id self, SEL sel) {
    (void)self; (void)sel;
    return NO;
}

static id hook_clLocation(id self, SEL sel) {
    if (g_ghost && (g_lat != 0 || g_lon != 0)) {
        return [[[CLLocation alloc] initWithLatitude:g_lat longitude:g_lon] autorelease];
    }
    return orig_clLocation ? orig_clLocation(self, sel) : nil;
}

// ---------- plumbing ----------
static void swizzle(Class c, SEL s, IMP n, IMP *save) {
    if (!c || !s || !n) return;
    Method m = class_getInstanceMethod(c, s);
    if (!m) return;
    *save = method_getImplementation(m);
    method_setImplementation(m, n);
}

void iris_objc_init(void) {
    iris_read_config();

    Class nc = [NSNotificationCenter class];
    swizzle(nc, @selector(postNotificationName:object:userInfo:),
            (IMP)hook_post3, (IMP *)&orig_post3);
    swizzle(nc, @selector(postNotification:),
            (IMP)hook_post1, (IMP *)&orig_post1);

    Class scr = NSClassFromString(@"UIScreen");
    swizzle(scr, @selector(isCaptured), (IMP)hook_isCaptured, (IMP *)&orig_isCaptured);
    swizzle(scr, @selector(captured), (IMP)hook_captured, (IMP *)&orig_captured);

    Class lm = NSClassFromString(@"CLLocationManager");
    swizzle(lm, @selector(location), (IMP)hook_clLocation, (IMP *)&orig_clLocation);
}
