//
//  AppDelegate.m
//  MacBox
//
//  Created by Mark on 01/08/2017.
//  Copyright © 2017 Mark McGuill. All rights reserved.
//

#import "AppDelegate.h"
#import "DocumentController.h"
#import "Settings.h"
#import "UpgradeWindowController.h"
#import "Alerts.h"
#import "Utils.h"
#import "Strongbox.h"
#import "PreferencesWindowController.h"
#import "SafesMetaDataViewer.h"
#import "BiometricIdHelper.h"
//#import "DAVKit.h"

//#define kIapFullVersionStoreId @"com.markmcguill.strongbox.test.consumable"
#define kIapFullVersionStoreId @"com.markmcguill.strongbox.mac.pro"

@interface AppDelegate ()

@property (strong) IBOutlet NSMenu *systemTraymenu;
@property NSStatusItem* statusItem;

@property (nonatomic) BOOL applicationHasFinishedLaunching;
@property (nonatomic, strong) SKProductsRequest *productsRequest;
@property (nonatomic, strong) NSArray<SKProduct *> *validProducts;
@property (strong, nonatomic) UpgradeWindowController *upgradeWindowController;
@property (strong, nonatomic) SafesMetaDataViewer *safesMetaDataViewer;
@property (strong, nonatomic) dispatch_block_t autoLockWorkBlock;
@property NSTimer* clipboardChangeWatcher;
@property NSInteger currentClipboardVersion;

@end

@implementation AppDelegate

- (id)init {
    self = [super init];
    
    // Bizarre but to subclass NSDocumentController you must instantiate your document here, no need to assign
    // it anywhere it just picks it up by "magic" very strange...
    
    DocumentController *dc = [[DocumentController alloc] init];
    
    if(dc) {} // Unused Warning evasion...
    
    return self;
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    [self removeUnwantedMenuItems];
    [self removeCopyDiagnosticDumpItem];
    
    [self removeShowSafesMetaDataItem];
    
    //BiometricIdHelper.sharedInstance.dummyMode = YES; // DEBUG
    
    if(!Settings.sharedInstance.fullVersion) {
        [self getValidIapProducts];

        if(![Settings sharedInstance].freeTrial){
            // Do not message for Upgrade until at least a while after initial open (per Apple guidelines)

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(180 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^ {
                [self randomlyShowUpgradeMessage];
            });
        }
    
        if([Settings sharedInstance].endFreeTrialDate == nil) {
            [self initializeFreeTrialAndShowWelcomeMessage];
        }
    }
    else {
        [self removeUpgradeMenuItem];
    }
    
    self.applicationHasFinishedLaunching = YES;

//    DAVCredentials *credentials = [DAVCredentials credentialsWithUsername:@"" password:@""];
//    DAVSession *session = [[DAVSession alloc] initWithRootURL:@"" credentials:credentials];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(onPreferencesChanged:) name:kPreferencesChangedNotification object:nil];
    
    // TODO: System Tray Icon
//    NSImage* statusImage = [NSImage imageNamed:@"Strongbox-36x26-inverted-bw"];
//    statusImage.size = NSMakeSize(18.0, 18.0);
//    self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSSquareStatusItemLength];
//    self.statusItem.image = statusImage;
//    self.statusItem.highlightMode = YES;
//    self.statusItem.enabled = YES;
//    self.statusItem.menu = self.systemTraymenu;
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    if(Settings.sharedInstance.clearClipboardEnabled) {
        [self clearClipboardIfChangeCountMatches];
    }
}

- (void)applicationDidBecomeActive:(NSNotification *)notification {
    if(self.autoLockWorkBlock) {
        dispatch_block_cancel(self.autoLockWorkBlock);
        self.autoLockWorkBlock = nil;
    }
}

- (void)applicationDidResignActive:(NSNotification *)notification {
    NSInteger timeout = [[Settings sharedInstance] autoLockTimeoutSeconds];
    
    if(timeout != 0) {
        self.autoLockWorkBlock = dispatch_block_create(0, ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:kAutoLockTime object:nil];
            
            self.autoLockWorkBlock = nil;
        });
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC)), dispatch_get_main_queue(), self.autoLockWorkBlock);
    }
}

- (void)initializeFreeTrialAndShowWelcomeMessage {
    NSCalendar *cal = [NSCalendar currentCalendar];
    NSDate *date = [cal dateByAddingUnit:NSCalendarUnitMonth value:2 toDate:[NSDate date] options:0];
    
    [Settings sharedInstance].endFreeTrialDate = date;
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [Alerts info:@"Welcome to Strongbox"
     informativeText:@"Hi and welcome to Strongbox!\n\n"
         @"I hope you'll really like the app, and find it useful. You can enjoy this fully featured Pro version of Strongbox for the next couple of months. "
         @"After that point, you will be transitioned to the regular version of Strongbox.\n\n"
         @"You can always find out more at any time by tapping 'Upgrade to Pro' in the Strongbox menu item.\n\n"
         @"Thanks!\n-Mark"
              window:[NSApplication sharedApplication].mainWindow 
          completion:nil];
    });
}

- (void)randomlyShowUpgradeMessage {
    NSUInteger random = arc4random_uniform(100);
    
    if(random % 3 == 0) {
        [((AppDelegate*)[[NSApplication sharedApplication] delegate]) showUpgradeModal:3];
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)getValidIapProducts {
    NSSet *productIdentifiers = [NSSet setWithObjects:kIapFullVersionStoreId, nil];
    self.productsRequest = [[SKProductsRequest alloc] initWithProductIdentifiers:productIdentifiers];
    self.productsRequest.delegate = self;
    [self.productsRequest start];
}

-(void)productsRequest:(SKProductsRequest *)request
    didReceiveResponse:(SKProductsResponse *)response
{
    dispatch_async(dispatch_get_main_queue(), ^{
        [self appStoreProductRequestCompleted:response.products error:nil];
    });
}

- (void)request:(SKRequest *)request didFailWithError:(NSError *)error {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self appStoreProductRequestCompleted:nil error:error];
    });
}

- (void)appStoreProductRequestCompleted:(NSArray<SKProduct *> *)products error:(NSError*)error {
    if(products) {
        NSUInteger count = [products count];
        if (count > 0) {
            self.validProducts = products;
            for (SKProduct *validProduct in self.validProducts) {
                NSLog(@"%@", validProduct.productIdentifier);
                NSLog(@"%@", validProduct.localizedTitle);
                NSLog(@"%@", validProduct.localizedDescription);
                NSLog(@"%@", validProduct.price);
            }
        }
    }
    else {
        // Do not do this, violates Apple's rules at startup... no messaging
        // [Alerts error:@"Error Contacting App Store for Upgrade Info" error:error window:[NSApplication sharedApplication].mainWindow];
    }
}

- (BOOL)validateUserInterfaceItem:(id <NSValidatedUserInterfaceItem>)anItem {
    SEL theAction = [anItem action];
    
    if (theAction == @selector(onUpgradeToFullVersion:)) {
        return self.validProducts != nil;
    }

    return YES;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)removeUnwantedMenuItems {
    // Remove Start Dictation and Emoji menu Items
    
    NSMenu* edit = [[[[NSApplication sharedApplication] mainMenu] itemWithTitle: @"Edit"] submenu];
    
    if ([[edit itemAtIndex: [edit numberOfItems] - 1] action] == NSSelectorFromString(@"orderFrontCharacterPalette:")) {
        [edit removeItemAtIndex: [edit numberOfItems] - 1];
    }
    
    if ([[edit itemAtIndex: [edit numberOfItems] - 1] action] == NSSelectorFromString(@"startDictation:")) {
        [edit removeItemAtIndex: [edit numberOfItems] - 1];
    }
    
    if ([[edit itemAtIndex: [edit numberOfItems] - 1] isSeparatorItem]) {
        [edit removeItemAtIndex: [edit numberOfItems] - 1];
    }
    
    NSMenu *fileMenu = NSApp.mainMenu.itemArray[1].submenu;
    
    void (^removeItemWithSelector)(SEL) = ^void(SEL selector) {
        NSInteger idx = [fileMenu indexOfItemWithTarget:nil andAction:selector];
        if (idx != -1)
        {
            [fileMenu removeItemAtIndex:idx];
        }
    };

    // FUTURE: Figure out what's wrong with these guys!!`
    removeItemWithSelector(@selector(duplicateDocument:));
    removeItemWithSelector(@selector(saveDocumentAs:));
    
    //    removeItemWithSelector(@selector(moveDocument:));
    //    removeItemWithSelector(@selector(renameDocument:));

    [self removeMenuItem:@"File" action:@"saveDocumentAs:"];
}

- (void)removeShowSafesMetaDataItem {
    [self removeMenuItem:@"View" action:@"onViewSafesMetaData:"];
}

- (void)removeCopyDiagnosticDumpItem {
    [self removeMenuItem:@"Database" action:@"onCopyDiagnosticDump:"];
}

- (void)removeUpgradeMenuItem {
    [self removeMenuItem:@"Strongbox" action:@"onUpgradeToFullVersion:"];
}

- (void)removeMenuItem:(NSString*)topLevelTitle action:(NSString*)action {
    NSMenu* strongBox = [[[[NSApplication sharedApplication] mainMenu] itemWithTitle: topLevelTitle] submenu];
    
    NSUInteger index = [strongBox.itemArray indexOfObjectPassingTest:^BOOL(NSMenuItem * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        return obj.action == NSSelectorFromString(action);
    }];
    
    if(index != NSNotFound) {
        NSLog(@"Removing %@ from %@ Menu", action, topLevelTitle);
        [strongBox removeItemAtIndex:index];
    }
    else {
        NSLog(@"WARN: Menu Item %@ not found to remove.", action);
    }
}

- (BOOL)applicationShouldOpenUntitledFile:(NSApplication *)sender {
    if(!self.applicationHasFinishedLaunching) {
        // Get the recent documents
        NSDocumentController *controller =
        [NSDocumentController sharedDocumentController];
        NSArray *documents = [controller recentDocumentURLs];
        
        // If there is a recent document, try to open it.
        if ([documents count] > 0)
        {
            [controller openDocumentWithContentsOfURL:[documents objectAtIndex:0] display:YES completionHandler:^(NSDocument * _Nullable document, BOOL documentWasAlreadyOpen, NSError * _Nullable error) { ; }];

            return NO;
        }
    }
    
    return YES;
}

- (IBAction)onViewSafesMetaData:(id)sender {
    if(self.safesMetaDataViewer == nil) {
        self.safesMetaDataViewer = [[SafesMetaDataViewer alloc] initWithWindowNibName:@"SafesMetaDataViewer"];
        
        NSWindow *window = [NSApplication sharedApplication].mainWindow;
        
        [window beginSheet:self.safesMetaDataViewer.window completionHandler:^(NSModalResponse returnCode) {
            self.safesMetaDataViewer = nil;
        }];
    }
}

- (IBAction)onPreferences:(id)sender {
    [PreferencesWindowController.sharedInstance show];
}

- (IBAction)onUpgradeToFullVersion:(id)sender {
    [self showUpgradeModal:0];
}

- (void)showUpgradeModal:(NSInteger)delay {
    if(!self.validProducts || self.validProducts == 0) {
        [self getValidIapProducts];
    }
    else {
        SKProduct* product = [_validProducts objectAtIndex:0];        
        [UpgradeWindowController show:product cancelDelay:delay];
    }
}

- (IBAction)onEmailSupport:(id)sender {
    NSString* subject = [NSString stringWithFormat:@"Strongbox %@ Support", [Utils getAppVersion]];
    NSString* emailBody = @"Hi,\n\nI'm having some trouble with Strongbox.\n\n<Please include as much detail as possible here including screenshots where appropriate.>";
    NSString* toAddress = @"support@strongboxsafe.com";
    
    NSSharingService* emailService = [NSSharingService sharingServiceNamed:NSSharingServiceNameComposeEmail];
    emailService.recipients = @[toAddress];
    emailService.subject = subject;
    
    if ([emailService canPerformWithItems:@[emailBody]]) {
        [emailService performWithItems:@[emailBody]];
    } else {
        NSString *encodedSubject = [NSString stringWithFormat:@"SUBJECT=%@", [subject stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLFragmentAllowedCharacterSet]]];
        NSString *encodedBody = [NSString stringWithFormat:@"BODY=%@", [emailBody stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLFragmentAllowedCharacterSet]]];
        NSString *encodedTo = [toAddress stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLFragmentAllowedCharacterSet]];
        NSString *encodedURLString = [NSString stringWithFormat:@"mailto:%@?%@&%@", encodedTo, encodedSubject, encodedBody];
        NSURL *mailtoURL = [NSURL URLWithString:encodedURLString];
        
        if(![[NSWorkspace sharedWorkspace] openURL:mailtoURL]) {
            [Alerts info:@"Email Unavailable"
         informativeText:@"Strongbox could not initialize an email for you, perhaps because it is not configured.\n\n"
                        @"Please send an email to support@strongboxsafe.com with details of your issue."
                  window:[NSApplication sharedApplication].mainWindow
              completion:nil];
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Clipboard Clearing

- (void)onPreferencesChanged:(NSNotification*)notification {
    NSLog(@"Preferences Have Changed Notification Received... Resetting Clipboard Clearing Tasks");

    [self initializeClipboardWatchingTask];
}

- (void)applicationWillBecomeActive:(NSNotification *)notification {
//    NSLog(@"applicationWillBecomeActive");

    [self initializeClipboardWatchingTask];
}

- (void)initializeClipboardWatchingTask {
    [self killClipboardWatchingTask];
    
    if(Settings.sharedInstance.clearClipboardEnabled) {
        [self startClipboardWatchingTask];
    }
}

- (void)applicationWillResignActive:(NSNotification *)notification {
//    NSLog(@"applicationWillResignActive");
    [self killClipboardWatchingTask];
}

- (void)startClipboardWatchingTask {
//    NSLog(@"startClipboardWatchingTask...");
    self.currentClipboardVersion = -1;
    self.clipboardChangeWatcher = [NSTimer scheduledTimerWithTimeInterval:0.5f repeats:YES block:^(NSTimer * _Nonnull timer) {
        [self checkClipboardForChangesAndNotify];
    }];
}

- (void)killClipboardWatchingTask {
//    NSLog(@"killClipboardWatchingTask...");
    
    self.currentClipboardVersion = -1;
    
    if(self.clipboardChangeWatcher != nil) {
        [self.clipboardChangeWatcher invalidate];
        self.clipboardChangeWatcher = nil;
    }
}

- (void)checkClipboardForChangesAndNotify {
    //NSLog(@"Checking Clipboard = [%ld]", (long)NSPasteboard.generalPasteboard.changeCount);
    
    if(self.currentClipboardVersion == -1) { // Initial Watch - Record the current count and watch for changes from this
        self.currentClipboardVersion = NSPasteboard.generalPasteboard.changeCount;
    }
    
    if(self.currentClipboardVersion != NSPasteboard.generalPasteboard.changeCount) {
        [self onApplicationDidChangeClipboard];
        self.currentClipboardVersion = NSPasteboard.generalPasteboard.changeCount;
    }
}

static NSInteger clipboardChangeCount;

- (void)clearClipboardIfChangeCountMatches {
    if(clipboardChangeCount == NSPasteboard.generalPasteboard.changeCount) {
        NSLog(@"Clipboard change count matches after time delay... Clearing Clipboard");
        [NSPasteboard.generalPasteboard clearContents];
    }
    else {
        NSLog(@"Clipboard change count DOES NOT matches after time delay... NOP");
    }
}

- (void)onApplicationDidChangeClipboard {
    NSLog(@"onApplicationDidChangeClipboard...");
    
    if(Settings.sharedInstance.clearClipboardEnabled) {
        clipboardChangeCount = NSPasteboard.generalPasteboard.changeCount;
        NSLog(@"Clipboard Changed and Clear Clipboard Enabled... Recording Change Count as [%ld]", (long)clipboardChangeCount);
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(Settings.sharedInstance.clearClipboardAfterSeconds * NSEC_PER_SEC)),
           dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0L), ^{
               [self clearClipboardIfChangeCountMatches];
           });
    }
}

@end
