#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>

// Compile-time declarations only. kNeeds checks at runtime that they exist.
@interface NSObject (YTMinloadGetters)
@property (readonly) BOOL hasAdLoggingData, hasCompatibilityOptions, hasAdSlotRenderer, hasElementRenderer,
    hasItemSectionRenderer, hasCommand, hasReelWatchEndpoint, hasAdClientParams, isAd;
@property (readonly) NSObject *compatibilityOptions, *elementRenderer, *itemSectionRenderer, *command,
    *reelWatchEndpoint, *adClientParams;
@property (readonly) NSMutableArray *contentsArray;
@end

typedef struct {
    const char *cls;
    const char *sel;
    IMP imp;
    bool meta;  // class method
    IMP *orig;  // filter rows only: receives the original implementation
} Hook;

static BOOL RetYES(id self, SEL _cmd) { return YES; }
static BOOL RetNO(id self, SEL _cmd) { return NO; }
static id RetNil(id self, SEL _cmd) { return nil; }
static NSUInteger RetZero(id self, SEL _cmd) { return 0; }
// A new array per call: callers may mutate GPB repeated fields.
static id RetEmpty(id self, SEL _cmd) { return [NSMutableArray array]; }
// Also used for void methods with arguments. On arm64 they arrive in registers and are ignored.
static void Noop(id self, SEL _cmd) {}

// Resigning changes the team ID, so the SSO keychain group pinned to Google's team is unusable.
// A temporary keychain item reveals the access group this app can actually use.
static id RetAccessGroup(id self, SEL _cmd) {
    static NSString *group;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSDictionary *query = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrAccount: @"ytminload.accessGroup",
            (__bridge id)kSecAttrService: @"ytminload",
            (__bridge id)kSecReturnAttributes: @YES,
        };
        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        if (status == errSecItemNotFound) status = SecItemAdd((__bridge CFDictionaryRef)query, &result);
        NSDictionary *attrs = CFBridgingRelease(result);
        if (status == errSecSuccess) group = attrs[(__bridge id)kSecAttrAccessGroup];
    });
    return group;
}

// Getters the filter rows call. If any is missing, no filter row is installed. `ytm.py check` reads this list.
static const char *const kNeeds[][2] = {
    {"YTIElementRenderer", "hasCompatibilityOptions"},
    {"YTIElementRenderer", "compatibilityOptions"},
    {"YTIElementRendererCompatibilityOptions", "hasAdLoggingData"},
    {"YTIItemSectionSupportedRenderers", "hasAdSlotRenderer"},
    {"YTIItemSectionSupportedRenderers", "hasElementRenderer"},
    {"YTIItemSectionSupportedRenderers", "elementRenderer"},
    {"YTISectionListSupportedRenderers", "hasAdSlotRenderer"},
    {"YTISectionListSupportedRenderers", "hasItemSectionRenderer"},
    {"YTISectionListSupportedRenderers", "itemSectionRenderer"},
    {"YTIReelWatchSequenceEntry", "hasCommand"},
    {"YTIReelWatchSequenceEntry", "command"},
    {"YTICommand", "hasReelWatchEndpoint"},
    {"YTICommand", "reelWatchEndpoint"},
    {"YTIReelWatchEndpoint", "hasAdClientParams"},
    {"YTIReelWatchEndpoint", "adClientParams"},
    {"YTIReelAdClientParams", "isAd"},
};

static bool FiltersSupported(void) {
    for (const auto &n : kNeeds)
        if (!class_getInstanceMethod(objc_getClass(n[0]), sel_registerName(n[1]))) return false;
    return true;
}

typedef BOOL (^AdTest)(NSObject *item);

// Removes in place, not on a copy, because the app also calls the _Count getter.
// Returns YES if a non-empty list was all ads.
static BOOL RemoveAds(NSMutableArray *items, AdTest isAd) {
    NSIndexSet *ads = [items indexesOfObjectsPassingTest:^BOOL(id item, NSUInteger i, BOOL *stop) { return isAd(item); }];
    if (ads.count == 0) return NO;
    BOOL all = ads.count == items.count;
    [items removeObjectsAtIndexes:ads];
    return all;
}

static BOOL IsAdElement(NSObject *e) {
    return e.hasCompatibilityOptions && e.compatibilityOptions.hasAdLoggingData;
}

// Last line of defense: an ad element still in a list draws nothing, leaving a blank.
static IMP origElementData;
static id ElementData(NSObject *self, SEL _cmd) {
    if (IsAdElement(self)) return nil;
    return ((id (*)(id, SEL))origElementData)(self, _cmd);
}

// Marks the section when every item was an ad, so the section list drops the whole section.
static const void *kAllAdsKey = &kAllAdsKey;
static IMP origItemSectionContents;
static id ItemSectionContents(NSObject *self, SEL _cmd) {
    NSMutableArray *items = ((id (*)(id, SEL))origItemSectionContents)(self, _cmd);
    if (RemoveAds(items, ^BOOL(NSObject *i) {
            return i.hasAdSlotRenderer || (i.hasElementRenderer && IsAdElement(i.elementRenderer));
        }))
        objc_setAssociatedObject(self, kAllAdsKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return items;
}

static IMP origSectionListContents;
static id SectionListContents(NSObject *self, SEL _cmd) {
    NSMutableArray *sections = ((id (*)(id, SEL))origSectionListContents)(self, _cmd);
    RemoveAds(sections, ^BOOL(NSObject *s) {
        if (s.hasAdSlotRenderer) return YES;
        if (!s.hasItemSectionRenderer) return NO;
        NSObject *section = s.itemSectionRenderer;
        (void)[section contentsArray];  // runs the item filter first so kAllAdsKey is set
        return objc_getAssociatedObject(section, kAllAdsKey) != nil;
    });
    return sections;
}

// Drops videos marked isAd and every non-video entry. A non-video entry's ad marker exists only in
// sub-elements resolved at render time, and every non-video entry seen in diagnostics was an ad.
static BOOL IsAdEntry(NSObject *e) {
    if (!e.hasCommand || !e.command.hasReelWatchEndpoint) return YES;
    NSObject *endpoint = e.command.reelWatchEndpoint;
    return endpoint.hasAdClientParams && endpoint.adClientParams.isAd;
}

static id ReelEntries(IMP orig, NSObject *self, SEL _cmd) {
    NSMutableArray *entries = ((id (*)(id, SEL))orig)(self, _cmd);
    RemoveAds(entries, ^BOOL(NSObject *e) { return IsAdEntry(e); });
    return entries;
}

static IMP origEntries, origPrevEntries;
static id Entries(NSObject *self, SEL _cmd) { return ReelEntries(origEntries, self, _cmd); }
static id PrevEntries(NSObject *self, SEL _cmd) { return ReelEntries(origPrevEntries, self, _cmd); }

static void Install(const Hook &h, bool filters) {
    if (h.orig && !filters) return;
    Class cls = objc_getClass(h.cls);
    if (h.meta) cls = object_getClass(cls);
    SEL sel = sel_registerName(h.sel);
    // For GPB dynamic properties, this call creates the method via resolveInstanceMethod:.
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    if (h.orig) *h.orig = method_getImplementation(m);
    // Adds an override when the method is inherited, so only this class changes.
    class_replaceMethod(cls, sel, h.imp, method_getTypeEncoding(m));
}

__attribute__((constructor)) static void Init(void) {
    // Local, not global: a global table with function pointer casts would depend on C++ dynamic init order.
    const Hook hooks[] = {
        // A. Ads
        {"YTIPlayerResponse", "playerAdsArray", (IMP)RetEmpty},
        {"YTIPlayerResponse", "adSlotsArray", (IMP)RetEmpty},
        {"YTIPlayerResponse", "adParams", (IMP)RetNil},
        {"YTIPlayerResponse", "adNextParams", (IMP)RetNil},
        {"YTIPlayerResponse", "adBreakParams", (IMP)RetNil},
        {"YTIPlayerResponse", "playerAdsArray_Count", (IMP)RetZero},
        {"YTIPlayerResponse", "adSlotsArray_Count", (IMP)RetZero},
        {"YTIPlayerResponse", "hasAdNextParams", (IMP)RetNO},
        {"YTIPlayerResponse", "hasAdBreakParams", (IMP)RetNO},
        {"YTIPlayerResponse", "adBreakHeartbeatParams", (IMP)RetNil},
        {"YTIPlayerResponse", "hasAdBreakHeartbeatParams", (IMP)RetNO},
        {"YTIElementRenderer", "companionAd", (IMP)RetNil},
        {"YTIElementRenderer", "hasCompanionAdRenderer", (IMP)RetNO},
        // selrefs do not tell classes apart, so each called getter is hooked on every class that has it.
        {"YTIElementRenderer", "hasAppPromoCompanionAdRenderer", (IMP)RetNO},
        {"YTIElementRenderer", "hasShoppingCompanionAdRenderer", (IMP)RetNO},
        {"YTIElementRenderer", "hasSuggestedVideosCompanionAdRenderer", (IMP)RetNO},
        {"YTIPlayerCompanionAdsSupportedRenderers", "hasCompanionAdRenderer", (IMP)RetNO},
        {"YTIPlayerCompanionAdsSupportedRenderers", "hasAppPromoCompanionAdRenderer", (IMP)RetNO},
        {"YTIPlayerCompanionAdsSupportedRenderers", "hasShoppingCompanionAdRenderer", (IMP)RetNO},
        {"YTIPlayerCompanionAdsSupportedRenderers", "hasBelowPlayerAdLayoutRenderer", (IMP)RetNO},
        {"YTICompanionAdSupportedRenderers", "hasCompanionAdRenderer", (IMP)RetNO},
        {"YTICompanionAdSupportedRenderers", "hasAppPromoCompanionAdRenderer", (IMP)RetNO},
        {"YTICompanionAdSupportedRenderers", "hasShoppingCompanionAdRenderer", (IMP)RetNO},
        {"YTICompanionAdSupportedRenderers", "hasSuggestedVideosCompanionAdRenderer", (IMP)RetNO},
        {"YTICompanionAdSupportedRenderers", "hasBelowPlayerAdLayoutRenderer", (IMP)RetNO},
        {"YTISectionListSupportedRenderers", "hasCompanionAdRenderer", (IMP)RetNO},
        {"YTIWatchNextResponse", "adSlotsArray", (IMP)RetEmpty},
        {"YTIWatchNextResponse", "adSlotsArray_Count", (IMP)RetZero},
        {"YTIElementRenderer", "elementData", (IMP)ElementData, false, &origElementData},
        {"YTIItemSectionRenderer", "contentsArray", (IMP)ItemSectionContents, false, &origItemSectionContents},
        {"YTISectionListRenderer", "contentsArray", (IMP)SectionListContents, false, &origSectionListContents},
        {"YTIReelWatchSequenceResponse", "entriesArray", (IMP)Entries, false, &origEntries},
        {"YTIReelWatchSequenceResponse", "prevEntriesArray", (IMP)PrevEntries, false, &origPrevEntries},

        // B. Background playback
        {"YTIPlayabilityStatus", "isPlayableInBackground", (IMP)RetYES},
        {"MLVideo", "playableInBackground", (IMP)RetYES},
        {"YTIBackgroundOfflineSettingCategoryEntryRenderer", "isBackgroundEnabled", (IMP)RetYES},

        // C. Picture in Picture
        {"YTIIosMediaHotConfig", "enablePictureInPicture", (IMP)RetYES},
        {"YTIIosMediaHotConfig", "enablePipForNonPremiumUsers", (IMP)RetYES},
        {"YTIPlayabilityStatus", "isPlayableInPictureInPicture", (IMP)RetYES},

        // I. Upsell and prompts
        {"YTMealbarPromoController", "showMealbarPromoWithEvent:", (IMP)Noop},
        {"YTUpgradeControllerImpl", "showUpgradeDialog", (IMP)Noop},
        {"YTUpgradeControllerImpl", "showOldUpgradeDialog", (IMP)Noop},
        {"YTYouThereControllerImpl", "shouldShowYouTherePrompt", (IMP)RetNO},
        {"YTGlobalConfig", "shouldShowUpgrade", (IMP)RetNO},
        {"YTGlobalConfig", "shouldShowUpgradeDialog", (IMP)RetNO},

        // L. Sideload login
        {"SSOKeychainHelper", "accessGroup", (IMP)RetAccessGroup, true},
        {"SSOKeychainHelper", "sharedAccessGroup", (IMP)RetAccessGroup, true},
    };
    @autoreleasepool {
        bool filters = FiltersSupported();
        for (const Hook &h : hooks) Install(h, filters);
    }
}
