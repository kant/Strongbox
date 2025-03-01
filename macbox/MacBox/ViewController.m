//
//  ViewController.m
//  MacBox
//
//  Created by Mark on 01/08/2017.
//  Copyright © 2017 Mark McGuill. All rights reserved.
//

#import "ViewController.h"
#import "Alerts.h"
#import "CreateFormatAndSetCredentialsWizard.h"
#import "Settings.h"
#import "AppDelegate.h"
#import "Utils.h"
#import "CHCSVParser.h"
#import <LocalAuthentication/LocalAuthentication.h>
#import "SafesList.h"
#import "BiometricIdHelper.h"
#import "PreferencesWindowController.h"
#import "Csv.h"
#import "AttachmentItem.h"
#import "CustomField.h"
#import "Entry.h"
#import "KeyFileParser.h"
#import "ProgressWindow.h"
#import "SelectPredefinedIconController.h"
#import "KeePassPredefinedIcons.h"
#import "MacKeePassHistoryController.h"
#import "MacNodeIconHelper.h"
#import "Node+OtpToken.h"
#import "OTPToken+Generation.h"
#import "NodeDetailsWindowController.h"
#import "MBProgressHUD.h"
#import "CustomFieldTableCellView.h"


#define kDragAndDropUti @"com.markmcguill.strongbox.drag.and.drop.internal.uti"

const int kMaxRecommendCustomIconSize = 128*1024;
const int kMaxCustomIconDimension = 256;

static NSString* const kPasswordCellIdentifier = @"CustomFieldValueCellIdentifier";
static NSString* const kDefaultNewTitle = @"Untitled";

@interface ViewController ()

@property (strong, nonatomic) MacKeePassHistoryController *keePassHistoryController;
@property (strong, nonatomic) SelectPredefinedIconController* selectPredefinedIconController;
@property (strong, nonatomic) CreateFormatAndSetCredentialsWizard *changeMasterPassword;
@property (strong, nonatomic) ProgressWindow* progressWindow;
@property (nonatomic) BOOL showPassword;

@property NSMutableDictionary<NSUUID*, NSArray<Node*>*> *itemsCache;

@property NSTimer* timerRefreshOtp;
@property NSFont* italicFont;
@property NSFont* regularFont;

@property NSMutableDictionary<NSUUID*, NodeDetailsWindowController*>* detailsWindowControllers; // Required to keep a hold of these window objects or actions don't work!
@property (weak) IBOutlet NSTextField *labelTitle;
@property (weak) IBOutlet NSTextField *labelUsername;
@property (weak) IBOutlet NSTextField *labelEmail;
@property (weak) IBOutlet NSTextField *labelPassword;
@property (weak) IBOutlet NSTextField *labelUrl;
@property (weak) IBOutlet NSTextField *labelHiddenPassword;
@property (weak) IBOutlet ClickableImageView *imageViewTogglePassword;
@property (weak) IBOutlet NSView *totpRow;
@property (weak) IBOutlet NSTabView *quickViewColumn;
@property (weak) IBOutlet NSButton *buttonToggleQuickViewPanel;

@property (strong) IBOutlet NSMenu *outlineHeaderColumnsMenu;
@property (strong, nonatomic) ViewModel* model;
@property BOOL isPromptingAboutUnderlyingFileChange;
@property (weak) IBOutlet NSView *customFieldsRow;
@property (weak) IBOutlet NSTableView *customFieldsTable;
@property NSArray* customFields;

@end

static NSImage* kStrongBox256Image;

@implementation ViewController

+ (void)initialize {
    if(self == [ViewController class]) {
        kStrongBox256Image = [NSImage imageNamed:@"StrongBox-256x256"];
    }
}

- (void)viewDidAppear {
    [super viewDidAppear];
    
    [self initializeFullOrTrialOrLiteUI];
    
    [self setInitialFocus];
    
    [self startRefreshOtpTimer];
}

- (void)viewDidDisappear {
    [super viewDidDisappear];

    [self stopRefreshOtpTimer];

    [self closeAllDetailsWindows];
}

- (void)closeAllDetailsWindows {
    for (NodeDetailsWindowController *wc in [self.detailsWindowControllers.allValues copy]) { // Copy as race condition of windows closing and calling into us will lead to crash
        [wc close];
    }

    [self.detailsWindowControllers removeAllObjects];
}

- (IBAction)onViewItemDetails:(id)sender {
    [self showItemDetails];
}

- (void)showItemDetails {
    Node* item = [self getCurrentSelectedItem];
    [self openItemDetails:item newEntry:NO];
}

- (void)openItemDetails:(Node*)item newEntry:(BOOL)newEntry {
    if(!item || item.isGroup) {
        return;
    }
    
    NodeDetailsWindowController* wc = self.detailsWindowControllers[item.uuid];
    
    if(wc)
    {
        NSLog(@"Details window already exists... Activating... [%@]", wc);
        [wc showWindow:nil];
    }
    else {
        wc = [NodeDetailsWindowController showNode:item model:self.model parentViewController:self newEntry:newEntry];
        NSLog(@"Adding Details WindowController to List: [%@]", wc);
        self.detailsWindowControllers[item.uuid] = wc;
    }
}

- (void)onDetailsWindowClosed:(id)wc {
    NSLog(@"Removing Details WindowController to List: [%@]", wc);
    [self.detailsWindowControllers removeObjectForKey:wc];
}

- (void)viewDidLoad {
    [super viewDidLoad];

    self.detailsWindowControllers = [NSMutableDictionary dictionary];
    
    [self enableDragDrop];

    [self customizeUi];

    [self bindToModel];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(onAutoLock:) name:kAutoLockTime object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(onPreferencesChanged:) name:kPreferencesChangedNotification object:nil];
}

- (void)customizeUi {
    [self.tabViewLockUnlock setTabViewType:NSNoTabsNoBorder];
    [self.tabViewRightPane setTabViewType:NSNoTabsNoBorder];
    
    self.buttonUnlockWithTouchId.title = [NSString stringWithFormat:@"Unlock with %@", BiometricIdHelper.sharedInstance.biometricIdName];
    self.buttonUnlockWithTouchId.hidden = YES;
    
    self.imageViewTogglePassword.clickable = YES;
    self.imageViewTogglePassword.onClick = ^{
        [self onToggleShowHideQuickViewPassword:nil];
    };
    
    self.showPassword = Settings.sharedInstance.alwaysShowPassword;

    self.imageViewShowHidePassword.clickable = YES;
    self.imageViewShowHidePassword.showClickableBorder = NO;
    self.imageViewShowHidePassword.onClick = ^{
        self.textFieldMasterPassword.showsText = !self.textFieldMasterPassword.showsText;
        self.imageViewShowHidePassword.image = !self.textFieldMasterPassword.showsText ? [NSImage imageNamed:@"show"] : [NSImage imageNamed:@"hide"];
    };

    self.tableViewSummary.dataSource = self;
    self.tableViewSummary.delegate = self;
    
    [self.customFieldsTable registerNib:[[NSNib alloc] initWithNibNamed:@"CustomFieldTableCellView" bundle:nil] forIdentifier:@"CustomFieldValueCellIdentifier"];
    self.customFieldsTable.delegate = self;
    self.customFieldsTable.dataSource = self;
    self.customFieldsTable.doubleAction = @selector(onDoubleClickCustomField:);
    
    [self customizeOutlineView];
    
    self.quickViewColumn.hidden = !Settings.sharedInstance.revealDetailsImmediately;
    [self bindQuickViewButton];
}

- (void)customizeOutlineView {
    // TODO: Sorting...
    //self.outlineView.sortDescriptors = @[ [NSSortDescriptor sortDescriptorWithKey:@"title" ascending:YES] ];
    
    NSNib* nib = [[NSNib alloc] initWithNibNamed:@"CustomFieldTableCellView" bundle:nil];
    [self.outlineView registerNib:nib forIdentifier:kPasswordCellIdentifier];

    self.outlineView.usesAlternatingRowBackgroundColors = !Settings.sharedInstance.noAlternatingRows;
    self.outlineView.gridStyleMask = (Settings.sharedInstance.showVerticalGrid ? NSTableViewSolidVerticalGridLineMask : 0) | (Settings.sharedInstance.showHorizontalGrid ? NSTableViewSolidHorizontalGridLineMask : 0);
    
    self.outlineView.headerView.menu = self.outlineHeaderColumnsMenu;
    self.outlineView.autosaveTableColumns = YES;
    
    self.outlineView.delegate = self;
    self.outlineView.dataSource = self;
    
    [self bindColumnsToSettings];
}

- (void)bindColumnsToSettings {
    NSArray<NSString*>* visible = Settings.sharedInstance.visibleColumns;
    
    // Show / Hide...
    
    for (NSString* column in [Settings kAllColumns]) {
        [self showHideOutlineViewColumn:column show:[visible containsObject:column] && [self isColumnAvailableForModel:column]];
    }
    
    // Order...
    
    int i=0;
    for (NSString* column in visible) {
        NSInteger colIdx = [self.outlineView columnWithIdentifier:column];
        if(colIdx != -1) { // Perhaps we removed a column?!
            NSTableColumn *col = [self.outlineView.tableColumns objectAtIndex:colIdx];
            
            if(!col.hidden) { // Maybe hidden because it isn't available in this Model Format (Password Safe/KeePass)
                [self.outlineView moveColumn:colIdx toColumn:i++];
            }
        }
    }
    
//    [self.outlineView setColumnAutoresizingStyle:NSTableViewUniformColumnAutoresizingStyle];
}

- (IBAction)onOutlineHeaderColumnsChanged:(id)sender {
    NSMenuItem* menuItem = (NSMenuItem*)sender;
    
    //NSLog(@"Columns Changed: %@-%d", menuItem.identifier, menuItem.state == NSOnState);
    
    NSMutableArray<NSString*>* newColumns = [Settings.sharedInstance.visibleColumns mutableCopy];
    
    if(menuItem.state == NSOnState) // We are request to removing an existing column
    {
        [newColumns removeObject:menuItem.identifier];
        Settings.sharedInstance.visibleColumns = newColumns;
        [self showHideOutlineViewColumn:menuItem.identifier show:NO];
        [self.outlineView reloadData];
    }
    else { // We're adding a column
        if(![newColumns containsObject:menuItem.identifier]) { // Don't add a duplicate somehow
            [newColumns addObject:menuItem.identifier];
            Settings.sharedInstance.visibleColumns = newColumns;
        }
        [self showHideOutlineViewColumn:menuItem.identifier show:[self isColumnAvailableForModel:menuItem.identifier]];
        [self.outlineView reloadData];
    }
}

- (void)showHideOutlineViewColumn:(NSString*)identifier show:(BOOL)show {
    NSInteger colIdx = [self.outlineView columnWithIdentifier:identifier];
    NSTableColumn *col = [self.outlineView.tableColumns objectAtIndex:colIdx];
    
    //NSLog(@"Set hidden: %@->%d", col.identifier, !show);
    if(col.hidden != !show) {
        col.hidden = !show;
    }
}

- (BOOL)isColumnAvailableForModel:(NSString*)identifier {
    if(!self.model) {
        return NO;
    }
    
    BOOL ret;
    if (self.model.format == kPasswordSafe) {
        ret = (![identifier isEqualToString:kCustomFieldsColumn] && ![identifier isEqualToString:kAttachmentsColumn]);
    }
    else {
        ret = ![identifier isEqualToString:kEmailColumn];
    }
    
    //NSLog(@"isColumnAvailableForModel: %d = %@ -> %d", self.model.format == kPasswordSafe, identifier, ret);
    
    return ret;
}

- (BOOL)isColumnVisible:(NSString*)identifier {
    return [Settings.sharedInstance.visibleColumns containsObject:identifier];
}

- (void)disableFeaturesForLiteVersion {
    [self.searchField setPlaceholderString:@"Search Disabled - Please Upgrade"];
    self.searchField.enabled = NO;
    self.searchSegmentedControl.enabled = NO;
}

- (void)enableFeaturesForFullVersion {
    [self.searchField setPlaceholderString:@"Search (⌘F)"];
    self.searchField.enabled = YES;
    self.searchSegmentedControl.enabled = YES;
}

- (void)initializeFullOrTrialOrLiteUI {
    if(![Settings sharedInstance].fullVersion && ![Settings sharedInstance].freeTrial) {
        [self disableFeaturesForLiteVersion];
    }
    else {
        [self enableFeaturesForFullVersion];
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (NSImage * )getIconForNode:(Node *)vm large:(BOOL)large {
    return [MacNodeIconHelper getIconForNode:self.model vm:vm large:large];
}

- (void)onDeleteHistoryItem:(Node*)node historicalItem:(Node*)historicalItem {
    // NOP - Not displayed in main view...
    NSLog(@"Deleted History Item... no need to update UI");
}

- (void)onRestoreHistoryItem:(Node*)node historicalItem:(Node*)historicalItem {
    self.itemsCache = nil; // Clear items cache
    Node* selectionToMaintain = [self getCurrentSelectedItem];
    [self.outlineView reloadData]; // Full Reload required as item could be sorted to a different location
    NSInteger row = [self.outlineView rowForItem:selectionToMaintain];
    
    if(row != -1) {
        [self.outlineView selectRowIndexes:[NSIndexSet indexSetWithIndex:row] byExtendingSelection:NO];
        // This selection change will lead to a full reload of the details pane via selectionDidChange
    }
}

- (void)onDeleteItem:(Node*)node {
    self.itemsCache = nil; // Clear items cache
    [self.outlineView reloadData]; // Full reload in case we're in search and things have changed removing this item...
    [self bindDetailsPane];
}

- (void)onChangeParent:(Node*)node {
    self.itemsCache = nil; // Clear items cache
    [self.outlineView reloadData];
    [self bindDetailsPane];
}

//////////////

- (void)onItemIconChanged:(NSNotification*)notification {
    [self genericReloadOnUpdateAndMaintainSelection:notification popupMessage:@"Icon"];
}

- (void)onItemTitleChanged:(NSNotification*)notification {
    [self genericReloadOnUpdateAndMaintainSelection:notification popupMessage:@"Title"];
}

- (void)onItemPasswordChanged:(NSNotification*)notification {
    [self genericReloadOnUpdateAndMaintainSelection:notification popupMessage:@"Password"];
}

- (void)onItemUsernameChanged:(NSNotification*)notification {
    [self genericReloadOnUpdateAndMaintainSelection:notification popupMessage:@"Username"];
}

- (void)onItemEmailChanged:(NSNotification*)notification {
    [self genericReloadOnUpdateAndMaintainSelection:notification popupMessage:@"Email"];
}

- (void)onItemUrlChanged:(NSNotification*)notification {
    [self genericReloadOnUpdateAndMaintainSelection:notification popupMessage:@"URL"];
}

- (void)onItemNotesChanged:(NSNotification*)notification {
    [self genericReloadOnUpdateAndMaintainSelection:notification popupMessage:@"Notes"];
}

- (void)onCustomFieldsChanged:(NSNotification*)notification {
    [self genericReloadOnUpdateAndMaintainSelection:notification popupMessage:@"Custom Fields"];
}

- (void)onTotpChanged:(NSNotification*)notification {
    [self genericReloadOnUpdateAndMaintainSelection:notification popupMessage:@"TOTP"];
}

- (void)onAttachmentsChanged:(NSNotification*)notification {
    [self genericReloadOnUpdateAndMaintainSelection:notification popupMessage:@"Attachments"];
}

- (void)genericReloadOnUpdateAndMaintainSelection:(NSNotification*)notification popupMessage:(NSString*)popupMessage {
    if(notification.object != self.model) {
        return;
    }
    
    self.itemsCache = nil; // Clear items cache
    
    Node* selectionToMaintain = [self getCurrentSelectedItem];
    [self.outlineView reloadData]; // Full Reload required as item could be sorted to a different location
    
    if(selectionToMaintain) {
        NSInteger row = [self.outlineView rowForItem:selectionToMaintain];
        if(row != -1) {
            [self.outlineView selectRowIndexes:[NSIndexSet indexSetWithIndex:row] byExtendingSelection:NO];
        }
    }
    Node* node = (Node*)notification.userInfo[kNotificationUserInfoKeyNode];
    [self showPopupToastNotification:[NSString stringWithFormat:@"'%@' %@ Changed...", node.title, popupMessage]];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (BOOL)biometricOpenIsAvailableForSafe {
    SafeMetaData* metaData = [self getDatabaseMetaData];
    
    BOOL ret =  (metaData == nil ||
            !metaData.isTouchIdEnabled ||
            !(metaData.touchIdPassword || metaData.touchIdKeyFileDigest) ||
            !BiometricIdHelper.sharedInstance.biometricIdAvailable ||
    !(Settings.sharedInstance.fullVersion || Settings.sharedInstance.freeTrial));

    return !ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)resetModel:(ViewModel *)model {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self stopObservingModelChanges];
        [self closeAllDetailsWindows];
        
        self.model = model;
        
        [self bindToModel];
        [self setInitialFocus];
    });
}

- (void)bindToModel {
    [self stopObservingModelChanges];
    [self closeAllDetailsWindows];
    
    self.itemsCache = nil; // Clear items cache
    
    if(self.model == nil || self.model.locked) {
        [self.tabViewLockUnlock selectTabViewItemAtIndex:0];
        
        if(![self biometricOpenIsAvailableForSafe]) {
            self.buttonUnlockWithTouchId.hidden = YES;
            [self.buttonUnlockWithTouchId setKeyEquivalent:@""];
            [self.buttonUnlockWithPassword setKeyEquivalent:@"\r"];
        }
        else {
            self.buttonUnlockWithTouchId.hidden = NO;
            [self.buttonUnlockWithTouchId setKeyEquivalent:@"\r"];
            [self.buttonUnlockWithPassword setKeyEquivalent:@""];
        }
    }
    else {
        [self startObservingModelChanges];
        [self.tabViewLockUnlock selectTabViewItemAtIndex:1];
        
        [self bindColumnsToSettings];
        [self.outlineView reloadData];
        
        Node* selectedItem = [self.model getItemFromSerializationId:self.model.selectedItem];
        [self selectItem:selectedItem];
        
        [self bindDetailsPane];
    }
}

- (void)stopObservingModelChanges {
    if(self.model) {
        self.model.onNewItemAdded = nil;
        self.model.onDeleteItem = nil;
        self.model.onChangeParent = nil;
        self.model.onDeleteHistoryItem = nil;
        self.model.onRestoreHistoryItem = nil;
    }
    
    [NSNotificationCenter.defaultCenter removeObserver:self name:kModelUpdateNotificationCustomFieldsChanged object:nil];
    [NSNotificationCenter.defaultCenter removeObserver:self name:kModelUpdateNotificationTitleChanged object:nil];
    [NSNotificationCenter.defaultCenter removeObserver:self name:kModelUpdateNotificationUsernameChanged object:nil];
    [NSNotificationCenter.defaultCenter removeObserver:self name:kModelUpdateNotificationUrlChanged object:nil];
    [NSNotificationCenter.defaultCenter removeObserver:self name:kModelUpdateNotificationEmailChanged object:nil];
    [NSNotificationCenter.defaultCenter removeObserver:self name:kModelUpdateNotificationNotesChanged object:nil];
    [NSNotificationCenter.defaultCenter removeObserver:self name:kModelUpdateNotificationPasswordChanged object:nil];
    [NSNotificationCenter.defaultCenter removeObserver:self name:kModelUpdateNotificationIconChanged object:nil];
    [NSNotificationCenter.defaultCenter removeObserver:self name:kModelUpdateNotificationAttachmentsChanged object:nil];
    [NSNotificationCenter.defaultCenter removeObserver:self name:kModelUpdateNotificationTotpChanged object:nil];
}

- (void)startObservingModelChanges {
    __weak ViewController* weakSelf = self;
    self.model.onNewItemAdded = ^(Node * _Nonnull node, BOOL newRecord) {
        [weakSelf onNewItemAdded:node newRecord:newRecord];
    };
    self.model.onDeleteItem = ^(Node * _Nonnull node) {
        [weakSelf onDeleteItem:node];
    };
    self.model.onChangeParent = ^(Node * _Nonnull node) {
        [weakSelf onChangeParent:node];
    };
    self.model.onDeleteHistoryItem = ^(Node * _Nonnull item, Node * _Nonnull historicalItem) {
        [weakSelf onDeleteHistoryItem:item historicalItem:historicalItem];
    };
    self.model.onRestoreHistoryItem = ^(Node * _Nonnull item, Node * _Nonnull historicalItem) {
        [weakSelf onRestoreHistoryItem:item historicalItem:historicalItem];
    };
    
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(onCustomFieldsChanged:) name:kModelUpdateNotificationCustomFieldsChanged object:nil];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(onItemTitleChanged:) name: kModelUpdateNotificationTitleChanged object:nil];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(onItemUsernameChanged:) name: kModelUpdateNotificationUsernameChanged object:nil];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(onItemUrlChanged:) name: kModelUpdateNotificationUrlChanged object:nil];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(onItemEmailChanged:) name: kModelUpdateNotificationEmailChanged object:nil];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(onItemNotesChanged:) name: kModelUpdateNotificationNotesChanged object:nil];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(onItemPasswordChanged:) name:kModelUpdateNotificationPasswordChanged object:nil];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(onItemIconChanged:) name:kModelUpdateNotificationIconChanged object:nil];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(onAttachmentsChanged:) name:kModelUpdateNotificationAttachmentsChanged object:nil];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(onTotpChanged:) name:kModelUpdateNotificationTotpChanged object:nil];
}

- (void)setInitialFocus {
    if(self.model == nil || self.model.locked) {
        if([self biometricOpenIsAvailableForSafe]) {
            [self.view.window makeFirstResponder:self.buttonUnlockWithTouchId];
        }
        else {
            [self.textFieldMasterPassword becomeFirstResponder];
        }
    }
}

- (void)bindDetailsPane {
    Node* it = [self getCurrentSelectedItem];
    
    if(!it) {
        [self.tabViewRightPane selectTabViewItemAtIndex:2];
        [self.tableViewSummary reloadData];
    }
    else if (it.isGroup) {
        [self.tabViewRightPane selectTabViewItemAtIndex:1];
        self.imageViewGroupDetails.image = [self getIconForNode:it large:YES];
        self.imageViewGroupDetails.clickable = self.model.format != kPasswordSafe;
        self.imageViewGroupDetails.showClickableBorder = YES;
        self.imageViewGroupDetails.onClick = ^{ [self onEditNodeIcon:it]; };

        self.textFieldSummaryTitle.stringValue = [self maybeDereference:it.title node:it maybe:Settings.sharedInstance.dereferenceInQuickView];;
    }
    else {
        [self.tabViewRightPane selectTabViewItemAtIndex:0];
        self.emailRow.hidden = self.model.format != kPasswordSafe;
        
        //NSLog(@"Setting Text fields");
        self.labelTitle.stringValue = [self maybeDereference:it.title node:it maybe:Settings.sharedInstance.dereferenceInQuickView];
        self.labelPassword.stringValue = [self maybeDereference:it.fields.password node:it maybe:Settings.sharedInstance.dereferenceInQuickView];
        self.labelUrl.stringValue = [self maybeDereference:it.fields.url node:it maybe:Settings.sharedInstance.dereferenceInQuickView];
        self.labelUsername.stringValue = [self maybeDereference:it.fields.username node:it maybe:Settings.sharedInstance.dereferenceInQuickView];
        self.labelEmail.stringValue = it.fields.email;
        self.textViewNotes.string = [self maybeDereference:it.fields.notes node:it maybe:Settings.sharedInstance.dereferenceInQuickView];

        // Necessary to pick up links... :/
        
        [self.textViewNotes setEditable:YES];
        [self.textViewNotes checkTextInDocument:nil];
        [self.textViewNotes setEditable:NO];
        
        self.imageViewTogglePassword.hidden = (self.labelPassword.stringValue.length == 0 && !Settings.sharedInstance.concealEmptyProtectedFields);
        self.showPassword = Settings.sharedInstance.alwaysShowPassword || (self.labelPassword.stringValue.length == 0 && !Settings.sharedInstance.concealEmptyProtectedFields);
        [self showOrHideQuickViewPassword];
        
        // TOTP

        [self refreshOtpCode:nil];
        
        // Custom Fields
        
        NSArray* sortedKeys = [it.fields.customFields.allKeys sortedArrayUsingComparator:finderStringComparator];
        
        self.customFields = [sortedKeys map:^id _Nonnull(NSString * _Nonnull obj, NSUInteger idx) {
            CustomField* field = [[CustomField alloc] init];
            StringValue* value = it.fields.customFields[obj];
            
            field.key = obj;
            field.value = value.value;
            field.protected = value.protected;
            
            return field;
        }];
        
        self.customFieldsRow.hidden = self.model.format == kPasswordSafe || self.customFields.count == 0 || !Settings.sharedInstance.showCustomFieldsOnQuickViewPanel;
        [self.customFieldsTable reloadData];
    }
}

- (NSString*)maybeDereference:(NSString*)text node:(Node*)node maybe:(BOOL)maybe {
    return maybe ? [self.model dereference:text node:node] : text;
}
                                       
- (void)startRefreshOtpTimer {
    if(self.timerRefreshOtp == nil) {
        self.timerRefreshOtp = [NSTimer timerWithTimeInterval:1.0f target:self selector:@selector(refreshOtpCode:) userInfo:nil repeats:YES];
        [[NSRunLoop mainRunLoop] addTimer:self.timerRefreshOtp forMode:NSRunLoopCommonModes];
    }
}

- (void)stopRefreshOtpTimer {
    if(self.timerRefreshOtp) {
        [self.timerRefreshOtp invalidate];
        self.timerRefreshOtp = nil;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (BOOL)outlineView:(NSOutlineView *)outlineView isItemExpandable:(id)item
{
    if(!self.model || self.model.locked) {
        return NO;
    }
    
    if(item == nil) {
        NSArray<Node*> *items = [self getItems:self.model.rootGroup];
        
        return items.count > 0;
    }
    else {
        Node *it = (Node*)item;
        
        if(it.isGroup) {
            NSArray<Node*> *items = [self getItems:it];
            
            return items.count > 0;
        }
        else {
            return NO;
        }
    }
}

- (NSInteger)outlineView:(NSOutlineView *)outlineView numberOfChildrenOfItem:(id)item
{
    if(!self.model || self.model.locked) {
        return 0;
    }
    
    Node* group = (item == nil) ? self.model.rootGroup : ((Node*)item);
    NSArray<Node*> *items = [self getItems:group];
    return items.count;
}

- (id)outlineView:(NSOutlineView *)outlineView child:(NSInteger)index ofItem:(id)item {
    Node* group = (item == nil) ? self.model.rootGroup : ((Node*)item);
    NSArray<Node*> *items = [self getItems:group];
    return items.count == 0 ? nil : items[index];
}

- (id)outlineView:(NSOutlineView *)outlineView objectValueForTableColumn:(NSTableColumn *)theColumn byItem:(id)item
{
    return item;
}

- (BOOL)outlineView:(NSOutlineView *)outlineView isGroupItem:(id)item
{
    return NO;
}

- (nullable NSView *)outlineView:(NSOutlineView *)outlineView viewForTableColumn:(nullable NSTableColumn *)tableColumn item:(nonnull id)item {
    Node *it = (Node*)item;
    if([tableColumn.identifier isEqualToString:kTitleColumn]) {
        return [self getTitleCell:it];
    }
    else if([tableColumn.identifier isEqualToString:kUsernameColumn]) {
        return [self getEditableCell:it.fields.username node:it selector:@selector(onOutlineViewItemUsernameEdited:)];
    }
    else if([tableColumn.identifier isEqualToString:kPasswordColumn]) {
        CustomFieldTableCellView* cell = [self.outlineView makeViewWithIdentifier:kPasswordCellIdentifier owner:nil];
        
        NSString* password = [self maybeDereference:it.fields.password node:it maybe:Settings.sharedInstance.dereferenceInOutlineView];
        
        cell.value = it.isGroup ? @"" : password;
        cell.protected = !it.isGroup && !(password.length == 0 && !Settings.sharedInstance.concealEmptyProtectedFields);
        cell.valueHidden = !it.isGroup && !(password.length == 0 && !Settings.sharedInstance.concealEmptyProtectedFields);
        
        return cell;
    }
    else if([tableColumn.identifier isEqualToString:kTOTPColumn]) {
        NSString* totp = it.otpToken ? it.otpToken.password : @"";
        //NSLog(@"TOTP: %@", totp);
        NSTableCellView* cell = [self getReadOnlyCell:totp];

        if(it.otpToken) {
            uint64_t remainingSeconds = [self getTotpRemainingSeconds:item];
            
            cell.textField.textColor = (remainingSeconds < 5) ? NSColor.redColor : (remainingSeconds < 9) ? NSColor.orangeColor : NSColor.controlTextColor;
        }

        return cell;
    }
    else if([tableColumn.identifier isEqualToString:kURLColumn]) {
        return [self getUrlCell:it.fields.url node:it];
    }
    else if([tableColumn.identifier isEqualToString:kEmailColumn]) {
        return [self getEditableCell:it.fields.email node:it selector:@selector(onOutlineViewItemEmailEdited:)];
    }
    else if([tableColumn.identifier isEqualToString:kNotesColumn]) {
        return [self getEditableCell:it.fields.notes node:it selector:@selector(onOutlineViewItemNotesEdited:)];
    }
    else if([tableColumn.identifier isEqualToString:kAttachmentsColumn]) {
        return [self getReadOnlyCell:it.isGroup ? @"" : @(it.fields.attachments.count).stringValue];
    }
    else if([tableColumn.identifier isEqualToString:kCustomFieldsColumn]) {
        return [self getReadOnlyCell:it.isGroup ? @"" : @(it.fields.customFields.count).stringValue];
    }
    else {
        return [self getReadOnlyCell:@"< Unknown Column TO DO >"];
    }
}

- (NSTableCellView*)getReadOnlyCell:(NSString*)text {
    NSTableCellView* cell = (NSTableCellView*)[self.outlineView makeViewWithIdentifier:@"ReadOnlyCell" owner:self];
    cell.textField.stringValue = text;
    cell.textField.editable = NO;
    return cell;
}

- (NSTableCellView*)getUrlCell:(NSString*)text node:(Node*)node {
    NSTableCellView* cell = [self getEditableCell:text node:node selector:@selector(onOutlineViewItemUrlEdited:)];

    // MMcG: Valiant attempt but does not work well after edit, or indeed looks poor while selected...
    // no click functionality either... or selection of browser...
    
//    if(text.length) { // Absolutely required because NSDataDetector will die and kill us in strange ways otherwise...
//        NSDataDetector* detector = [NSDataDetector dataDetectorWithTypes:NSTextCheckingTypeLink error:nil];
//        if(detector) {
//            NSTextCheckingResult* result = [detector firstMatchInString:it.fields.url options:kNilOptions range:NSMakeRange(0, text.length)];
//            if (result.resultType == NSTextCheckingTypeLink && result.range.location == 0 && result.range.length == text.length) {
//                NSMutableAttributedString* attrString = [[NSMutableAttributedString alloc] initWithString:text];
//                NSRange range = NSMakeRange(0, [attrString length]);
//
//                [attrString beginEditing];
//
//                [attrString addAttribute:NSLinkAttributeName value:it.fields.url range:range];
//                [attrString addAttribute:NSForegroundColorAttributeName value:[NSColor systemBlueColor] range:range];
//                [attrString addAttribute:NSUnderlineStyleAttributeName value:[NSNumber numberWithInt:NSUnderlineStyleSingle] range:range];
//
//                [attrString endEditing];
//
//                cell.textField.attributedStringValue = attrString;
//            }
//        }
//    }

    return cell;
}

- (NSTableCellView*)getEditableCell:(NSString*)text node:(Node*)node selector:(SEL)selector {
    NSTableCellView* cell = (NSTableCellView*)[self.outlineView makeViewWithIdentifier:@"GenericCell" owner:self];
    
    cell.textField.stringValue = [self maybeDereference:text node:node maybe:Settings.sharedInstance.dereferenceInOutlineView];
    
    // Do not allow editing of dereferenced text in Outline View... impossible to work UI wise at the moment
    
    BOOL possiblyDereferencedText = Settings.sharedInstance.dereferenceInOutlineView && [self.model isDereferenceableText:text];
    
    cell.textField.editable = !possiblyDereferencedText && !Settings.sharedInstance.outlineViewEditableFieldsAreReadonly;
    cell.textField.action = selector;
    
    return cell;
}

- (NSTableCellView*)getTitleCell:(Node*)it {
    NSTableCellView* cell = (NSTableCellView*)[self.outlineView makeViewWithIdentifier:@"TitleCell" owner:self];
    if(!self.italicFont) {
        self.regularFont = cell.textField.font;
        self.italicFont = [NSFontManager.sharedFontManager convertFont:cell.textField.font toHaveTrait:NSFontItalicTrait];
    }
    
    if(it.isGroup && self.model.recycleBinEnabled && self.model.recycleBinNode && self.model.recycleBinNode == it) {
        cell.textField.font = self.italicFont;
    }
    else {
        cell.textField.font = self.regularFont;
    }

    cell.imageView.objectValue = [self getIconForNode:it large:NO];
    cell.textField.stringValue = [self maybeDereference:it.title node:it maybe:Settings.sharedInstance.dereferenceInOutlineView];

    BOOL possiblyDereferencedText = Settings.sharedInstance.dereferenceInOutlineView && [self.model isDereferenceableText:it.title];
    cell.textField.editable = !possiblyDereferencedText && !Settings.sharedInstance.outlineViewEditableFieldsAreReadonly;

    cell.textField.editable = !Settings.sharedInstance.outlineViewTitleIsReadonly;
    
    return cell;
}

- (void)outlineViewSelectionDidChange:(NSNotification *)notification {
    //NSLog(@"Selection Change Outline View");
    [self bindDetailsPane];
}

- (IBAction)onOutlineViewItemEmailEdited:(id)sender {
    Node *item = [self getCurrentSelectedItem];
    if(item == nil) {
        return;
    }
    
    NSTextField *textField = (NSTextField*)sender;
    NSString* newString =  [Utils trim:textField.stringValue];
    if(![item.fields.email isEqualToString:newString]) {
        [self.model setItemEmail:item email:newString];
    }
    else {
        textField.stringValue = newString;
    }
    
    [self.view.window makeFirstResponder:self.outlineView]; // Our TAB order is messed up... don't tab into next cell
}

- (IBAction)onOutlineViewItemNotesEdited:(id)sender {
    Node *item = [self getCurrentSelectedItem];
    if(item == nil) {
        return;
    }
    
    NSTextField *textField = (NSTextField*)sender;
    NSString* newString =  textField.stringValue;
    if(![item.fields.notes isEqualToString:newString]) {
        [self.model setItemNotes:item notes:newString];
    }
    else {
        textField.stringValue = newString;
    }
    
    [self.view.window makeFirstResponder:self.outlineView]; // Our TAB order is messed up... don't tab into next cell
}

- (IBAction)onOutlineViewItemUrlEdited:(id)sender {
    Node *item = [self getCurrentSelectedItem];
    if(item == nil) {
        return;
    }
    
    NSTextField *textField = (NSTextField*)sender;
    NSString* newString =  [Utils trim:textField.stringValue];
    if(![item.fields.url isEqualToString:newString]) {
        [self.model setItemUrl:item url:newString];
    }
    else {
        textField.stringValue = newString;
    }
    
    [self.view.window makeFirstResponder:self.outlineView]; // Our TAB order is messed up... don't tab into next cell
}

- (IBAction)onOutlineViewItemUsernameEdited:(id)sender {
    Node *item = [self getCurrentSelectedItem];
    if(item == nil) {
        return;
    }
    
    NSTextField *textField = (NSTextField*)sender;
    NSString* newString =  [Utils trim:textField.stringValue];
    if(![item.fields.username isEqualToString:newString]) {
        [self.model setItemUsername:item username:newString];
    }
    else {
        textField.stringValue = newString;
    }
    
    [self.view.window makeFirstResponder:self.outlineView]; // Our TAB order is messed up... don't tab into next cell
}

- (IBAction)onOutlineViewItemTitleEdited:(id)sender {
    Node *item = [self getCurrentSelectedItem];
    if(item == nil) {
        return;
    }
    
    NSTextField *textField = (NSTextField*)sender;
    
    NSString* newTitle = [Utils trim:textField.stringValue];
    if(![item.title isEqualToString:newTitle]) {
        if(![self.model setItemTitle:item title:newTitle]) {
            textField.stringValue = item.title;
        }
    }
    else {
        textField.stringValue = newTitle;
    }

    [self.view.window makeFirstResponder:self.outlineView]; // Our TAB order is messed up... don't tab into next cell
}

- (void)outlineView:(NSOutlineView *)outlineView sortDescriptorsDidChange:(NSArray<NSSortDescriptor *> *)oldDescriptors {
    // TODO: Sorting...
    NSLog(@"sortDescriptors did change!");
}

- (void)outlineViewColumnDidMove:(NSNotification *)notification {
    NSNumber* newNum = notification.userInfo[@"NSNewColumn"];

    NSTableColumn* column = self.outlineView.tableColumns[newNum.intValue];
    
    //NSLog(@"tableViewColumnDidMove: %@ -> %@", column.identifier, newNum);
    
    NSMutableArray<NSString*>* newColumns = [Settings.sharedInstance.visibleColumns mutableCopy];
   
    [newColumns removeObject:column.identifier];
    [newColumns insertObject:column.identifier atIndex:newNum.integerValue];
    
    Settings.sharedInstance.visibleColumns = newColumns;
}

- (IBAction)onOutlineViewDoubleClick:(id)sender {
    NSInteger colIdx = [sender clickedColumn];
    NSInteger rowIdx = [sender clickedRow];
    
    if(colIdx != -1 && rowIdx != -1) {
        NSTableColumn *col = [self.outlineView.tableColumns objectAtIndex:colIdx];
        Node *item = [sender itemAtRow:rowIdx];
        
        if([col.identifier isEqualToString:kTitleColumn]) {
            [self openItemDetails:item newEntry:NO];
        }
        else if([col.identifier isEqualToString:kUsernameColumn]) {
            [self copyUsername:item];
        }
        else if([col.identifier isEqualToString:kPasswordColumn]) {
            [self copyPassword:item];
        }
        else if([col.identifier isEqualToString:kTOTPColumn]) {
            [self copyTotp:item];
        }
        else if([col.identifier isEqualToString:kURLColumn]) {
            [self copyUrl:item];
        }
        else if([col.identifier isEqualToString:kEmailColumn]) {
            [self copyEmail:item];
        }
        else if([col.identifier isEqualToString:kNotesColumn]) {
            [self copyNotes:item];
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (NSArray<Node*> *)getItems:(Node*)parentGroup {
    if(!self.model || self.model.locked) {
        NSLog(@"Request for safe items while model nil or locked!");
        return @[];
    }
    
    if(self.itemsCache == nil) {
        self.itemsCache = [NSMutableDictionary dictionary];
    }
    
    if(self.itemsCache[parentGroup.uuid] == nil) {
        NSArray<Node*>* items = [self loadItems:parentGroup];
        self.itemsCache[parentGroup.uuid] = items;
    }
    
    return self.itemsCache[parentGroup.uuid];
}

-(NSArray<Node*>*)loadItems:(Node*)parentGroup {
    //NSLog(@"loadSafeItems for [%@]", parentGroup.uuid);
    if(!parentGroup.isGroup) { // This can actually happen somehow - onAttachmentsChanged
        return @[];
    }
    
    BOOL sort = !Settings.sharedInstance.uiDoNotSortKeePassNodesInBrowseView || self.model.format == kPasswordSafe;
    
    NSArray<Node*>* sorted = sort ? [parentGroup.children sortedArrayUsingComparator:finderStyleNodeComparator] : parentGroup.children;
    
    NSString* searchText = self.searchField.stringValue;
    if(![searchText length]) {
        // Filter Recycle Bin if Required in Browse
        if(Settings.sharedInstance.doNotShowRecycleBinInBrowse && self.model.recycleBinNode) {
            return [sorted filter:^BOOL(Node * _Nonnull obj) {
                return obj != self.model.recycleBinNode;
            }];
        }
        
        return sorted;
    }
    else {
        // Filter Recycle Bin if Required in Search - also TODO: KeePass1 Backup Group, Expired etc...
        if(!Settings.sharedInstance.showRecycleBinInSearchResults && self.model.recycleBinNode) {
            sorted = [sorted filter:^BOOL(Node * _Nonnull obj) {
                return obj != self.model.recycleBinNode;
            }];
        }
    }

    // Filter by Search term
    
    return [sorted filter:^BOOL(Node * _Nonnull obj) {
        return [self isSafeItemMatchesSearchCriteria:obj recurse:YES];
    }];
}

- (BOOL)isSafeItemMatchesSearchCriteria:(Node*)item recurse:(BOOL)recurse {
    NSString* searchText = self.searchField.stringValue;
    if(![searchText length]) {
        return YES;
    }
    
    if([self immediateMatch:searchText item:item scope:self.searchSegmentedControl.selectedSegment]) {
        return YES;
    }
    
    if(item.isGroup && recurse) {
        for(Node* child in item.children) {
            if([self isSafeItemMatchesSearchCriteria:child recurse:YES]) {
                return YES;
            }
        }
    }
    
    return NO;
}

- (BOOL)immediateMatch:(NSString*)searchText item:(Node*)item scope:(NSInteger)scope {
    BOOL immediateMatch = NO;

    NSArray<NSString*> *terms = [self.model getSearchTerms:searchText];
    
    //NSLog(@"Searching for Terms: [%@]", terms);
    
    for (NSString* term in terms) {
        if (scope == kSearchScopeTitle) {
            immediateMatch = [self.model isTitleMatches:term node:item dereference:Settings.sharedInstance.dereferenceDuringSearch];
        }
        else if (scope == kSearchScopeUsername) {
            immediateMatch = [self.model isUsernameMatches:term node:item dereference:Settings.sharedInstance.dereferenceDuringSearch];
        }
        else if (scope == kSearchScopePassword) {
            immediateMatch = [self.model isPasswordMatches:term node:item dereference:Settings.sharedInstance.dereferenceDuringSearch];
        }
        else if (scope == kSearchScopeUrl) {
            immediateMatch = [self.model isUrlMatches:term node:item dereference:Settings.sharedInstance.dereferenceDuringSearch];
        }
        else {
            immediateMatch = [self.model isAllFieldsMatches:term node:item dereference:Settings.sharedInstance.dereferenceDuringSearch];
        }
        
        if(!immediateMatch) { // MUST match all terms...
            return NO;
        }
    }
    
    return immediateMatch;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (NSString*)selectedItemSerializationId {
    Node* item = [self getCurrentSelectedItem];
    return item ? [item getSerializationId:self.model.format != kPasswordSafe] : nil;
}

- (SafeMetaData*)getDatabaseMetaData {
    if(!self.model || !self.model.fileUrl) {
        return nil;
    }
    
    return [SafesList.sharedInstance.snapshot firstOrDefault:^BOOL(SafeMetaData * _Nonnull obj) {
        return [obj.fileIdentifier isEqualToString:self.model.fileUrl.absoluteString];
    }];
}

- (void)showProgressModal:(NSString*)operationDescription {
    [self hideProgressModal];
    
    self.progressWindow = [[ProgressWindow alloc] initWithWindowNibName:@"ProgressWindow"];
    self.progressWindow.operationDescription = operationDescription;
    [self.view.window beginSheet:self.progressWindow.window  completionHandler:nil];
}

- (void)hideProgressModal {
    if(self.progressWindow) {
        [self.view.window endSheet:self.progressWindow.window];
        self.progressWindow = nil;
    }
}

- (IBAction)onUseKeyFileOnly:(id)sender {
    [self onUseKeyFileCommon:nil];
}

- (IBAction)onUseKeyFile:(id)sender {
    [self onUseKeyFileCommon:self.textFieldMasterPassword.stringValue];
}

- (void)onUseKeyFileCommon:(NSString*)password {
    NSOpenPanel *openPanel = [NSOpenPanel openPanel];
    [openPanel beginSheetModalForWindow:self.view.window completionHandler:^(NSInteger result){
        if (result == NSFileHandlingPanelOKButton) {
            NSLog(@"Open Key File: %@", openPanel.URL);
            
            NSError* error;
            NSData* data = [NSData dataWithContentsOfURL:openPanel.URL options:kNilOptions error:&error];
            
            if(!data) {
                NSLog(@"Could not read file at %@. Error: %@", openPanel.URL, error);
                [Alerts error:@"Could not open key file." error:error window:self.view.window];
                return;
            }
            
            NSData* keyFileDigest = [KeyFileParser getKeyFileDigestFromFileData:data checkForXml:YES]; // TODO: Wrong KDB Xml
            [self reloadAndUnlock:password keyFileDigest:keyFileDigest isBiometricOpen:NO];
        }
    }];
}

- (IBAction)onEnterMasterPassword:(id)sender {
    [self reloadAndUnlock:self.textFieldMasterPassword.stringValue keyFileDigest:nil isBiometricOpen:NO];
}

- (IBAction)onUnlockWithTouchId:(id)sender {
    if(BiometricIdHelper.sharedInstance.biometricIdAvailable) {
        SafeMetaData *metadata = [self getDatabaseMetaData];
        
        if(metadata && metadata.isTouchIdEnabled && (metadata.touchIdPassword || metadata.touchIdKeyFileDigest)) {
            [BiometricIdHelper.sharedInstance authorize:^(BOOL success, NSError *error) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    if(success) {
                        [self reloadAndUnlock:metadata.touchIdPassword keyFileDigest:metadata.touchIdKeyFileDigest isBiometricOpen:YES];
                    }
                    else {
                        NSLog(@"Error unlocking safe with Touch ID. [%@]", error);
                        
                        if(error && (error.code == LAErrorUserFallback || error.code == LAErrorUserCancel)) {
                            NSLog(@"User cancelled or selected fallback. Ignore...");
                        }
                        else {
                            [Alerts error:error window:self.view.window];
                        }
                    }
                });}];
        }
        else {
            NSLog(@"Touch ID button pressed but no Touch ID Stored?");
            [Alerts info:@"The stored credentials are unavailable. Please enter the password manually. Touch ID Metadata for this database will be cleared." window:self.view.window];
            if(metadata) {
                [SafesList.sharedInstance remove:metadata.uuid];
            }
        }
    }
}

- (void)onFileChangedByOtherApplication {
    if(self.isPromptingAboutUnderlyingFileChange) {
        NSLog(@"Already in Use...");
        return;
    }
    
    self.isPromptingAboutUnderlyingFileChange = YES;
    if(self.model && !self.model.locked) {
        if(!self.model.document.isDocumentEdited) {
            if(!Settings.sharedInstance.autoReloadAfterForeignChanges) {
                [Alerts yesNo:@"The database has been changed by another application, would you like to reload this latest version and automatically unlock?"
                       window:self.view.window
                   completion:^(BOOL yesNo) {
                    if(yesNo) {
                        [self showPopupToastNotification:@"Reloading after external changes..."];
                        
                        self.model.selectedItem = [self selectedItemSerializationId];
                        [self reloadAndUnlock:self.model.masterPassword keyFileDigest:self.model.masterKeyFileDigest isBiometricOpen:NO];
                    }
                }];
                return;
            }
            else {
                [self showPopupToastNotification:@"Reloading after external changes..."];

                self.model.selectedItem = [self selectedItemSerializationId];
                [self reloadAndUnlock:self.model.masterPassword keyFileDigest:self.model.masterKeyFileDigest isBiometricOpen:NO];
                return;
            }
        }
        else {
            NSLog(@"Local Changes Present... ignore this, we can't auto reload...");
        }
    }
    else {
        NSLog(@"Ignoring File Change by Other Application because Database is locked/not set.");
    }
    self.isPromptingAboutUnderlyingFileChange = NO;
}

- (void)reloadAndUnlock:(NSString*)password keyFileDigest:(NSData*)keyFileDigest isBiometricOpen:(BOOL)isBiometricOpen {
    if(self.model) {
        [self showProgressModal:@"Unlocking..."];
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [self.model reloadAndUnlock:password keyFileDigest:keyFileDigest completion:^(BOOL success, NSError * _Nullable error) {
                [self hideProgressModal];
                if(success) {
                    self.textFieldMasterPassword.stringValue = @"";
                }
                [self onUnlocked:success error:error password:password keyFileDigest:keyFileDigest isBiometricUnlock:isBiometricOpen];
            }];
        });
    }
}

- (void)onUnlocked:(BOOL)success
             error:(NSError*)error
          password:(NSString*)password
     keyFileDigest:(NSData*)keyFileDigest
 isBiometricUnlock:(BOOL)isBiometricUnlock {
    if(success) {
        [self maybePromptForBiometricEnrol:password
                             keyFileDigest:keyFileDigest];
    }
    else {
        if(isBiometricUnlock) {
            SafeMetaData *safe = [self getDatabaseMetaData];
            [SafesList.sharedInstance remove:safe.uuid]; // FUTURE: Maybe we shouldn't remove but code relies on this to ask/prompt for Touch ID
        }
        
        [Alerts error:@"Could Not Unlock Database" error:error window:self.view.window];
    }
    
    self.isPromptingAboutUnderlyingFileChange = NO;// Reset in case we ended up here by auto reload
}

- (void)maybePromptForBiometricEnrol:(NSString*)password keyFileDigest:(NSData*)keyFileDigest {
    if ( BiometricIdHelper.sharedInstance.biometricIdAvailable && (Settings.sharedInstance.fullVersion || Settings.sharedInstance.freeTrial)) {
        //NSLog(@"Biometric ID is available on Device. Should we enrol?");
        SafeMetaData* metaData = [self getDatabaseMetaData];
        
        if(!metaData) {
            NSString* message = [NSString stringWithFormat:@"Would you like to use %@ to open this database in the future?", BiometricIdHelper.sharedInstance.biometricIdName];
            
            [Alerts yesNo:message
                   window:self.view.window
               completion:^(BOOL yesNo) {
                   NSURL* url = self.model.fileUrl;
                   SafeMetaData* safeMetaData = [[SafeMetaData alloc] initWithNickName:[url.lastPathComponent stringByDeletingPathExtension]
                                                                       storageProvider:kLocalDevice
                                                                              fileName:url.lastPathComponent
                                                                        fileIdentifier:url.absoluteString];
                   
                   if(yesNo) {
                       safeMetaData.isTouchIdEnabled = YES;
                       safeMetaData.touchIdPassword = password;
                       safeMetaData.touchIdKeyFileDigest = keyFileDigest;
                       
                       [self caveatAboutTouchId];
                   }
                   else {
                       safeMetaData.isTouchIdEnabled = NO;
                   }
                   
                   [SafesList.sharedInstance add:safeMetaData];
               }];
        }
    }
}

- (void)caveatAboutTouchId {
    if(!Settings.sharedInstance.warnedAboutTouchId) { // First Time? Display Touch ID Caveat
        Settings.sharedInstance.warnedAboutTouchId = YES;
        
        [Alerts info:@"Touch ID Considerations\n\nWhile this is very convenient, it is not a perfect system for protecting your passwords. It is provided for convenience only. It is within the realm of possibilities that someone with access to your device or your fingerprint, can produce a good enough fake fingerprint to fool Apple’s Touch ID. In addition, on your Mac, your master password will be securely stored in the Keychain. This means it is possible for someone with administrative privileges to search your Keychain for your master password. You should be aware that a strong passphrase held only in your mind provides the most secure experience with StrongBox.\n\nPlease take all of this into account, and make your decision to use Touch ID based on your preferred balance of convenience and security."
              window:self.view.window];
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)onAutoLock:(NSNotification*)notification {
    if(self.model && !self.model.locked && !self.model.document.isDocumentEdited) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self onLock:nil];
        });
    }
}

- (IBAction)onLock:(id)sender {
    if(self.model && !self.model.locked) {
//        NSLog(@"isDocumentEdited: %d", self.model.document.isDocumentEdited);
        if([self.model.document isDocumentEdited]) {
            [Alerts yesNo:@"You cannot lock a database while changes are pending. Save changes and lock now?" window:self.view.window completion:^(BOOL yesNo) {
                if(yesNo) {
                    [self showProgressModal:@"Locking..."];
                    [self.model.document saveDocumentWithDelegate:self didSaveSelector:@selector(lockSafeContinuation:) contextInfo:nil];
                }
                else {
                    return;
                }
            }];
        }
        else {
            [self showProgressModal:@"Locking..."];

            [self lockSafeContinuation:nil];
        }
    }
}

- (IBAction)lockSafeContinuation:(id)sender {
    NSString* sid = [self selectedItemSerializationId];
    [self closeAllDetailsWindows];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self.model lock:sid];
        dispatch_async(dispatch_get_main_queue(), ^{
            [self onLockDone];
        });
    });
}

- (void)onLockDone {
    [self hideProgressModal];
    
    [self bindToModel];
    
    self.textFieldMasterPassword.stringValue = @"";
    [self setInitialFocus];
    
    [self.view setNeedsDisplay:YES];
    
    // Finally Clear Clipboard if so configured...
    
    if(Settings.sharedInstance.clearClipboardEnabled) {
        AppDelegate* appDelegate = (AppDelegate*)[NSApplication sharedApplication].delegate;
        [appDelegate clearClipboardIfChangeCountMatches];
    }
}

- (void)promptForMasterPassword:(BOOL)new completion:(void (^)(BOOL okCancel))completion {
    if(self.model && !self.model.locked) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self.changeMasterPassword = [[CreateFormatAndSetCredentialsWizard alloc] initWithWindowNibName:@"ChangeMasterPasswordWindowController"];
            
            self.changeMasterPassword.titleText = new ? @"Please Enter the Master Credentials for this Database" : @"Change Master Credentials";
            self.changeMasterPassword.databaseFormat = self.model.format;
            
            [self.view.window beginSheet:self.changeMasterPassword.window  completionHandler:^(NSModalResponse returnCode) {
                if(returnCode == NSModalResponseOK) {
                    [self.model setMasterCredentials:self.changeMasterPassword.confirmedPassword masterKeyFileDigest:self.changeMasterPassword.confirmedKeyFileDigest];
                }
                
                if(completion) {
                    completion(returnCode == NSModalResponseOK);
                }
            }];
        });
    }
}

- (IBAction)onChangeMasterPassword:(id)sender {
    [self promptForMasterPassword:NO completion:^(BOOL okCancel) {
        if(okCancel) {
            [[NSApplication sharedApplication] sendAction:@selector(saveDocument:) to:nil from:self];
            [Alerts info:@"Master Credentials Changed and Database Saved" window:self.view.window];
        }
    }];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (IBAction)onFind:(id)sender {
    [self.view.window makeFirstResponder:self.searchField];
}

- (IBAction)onSearch:(id)sender {    
    self.itemsCache = nil; // Clear items cache
    
    Node* currentSelection = [self getCurrentSelectedItem];
    
    [self.outlineView reloadData];
    
    if( self.searchField.stringValue.length > 0) {
        // Select first match...
        
        [self.outlineView expandItem:nil expandChildren:YES];

        for(int i=0;i < [self.outlineView numberOfRows];i++) {
            //NSLog(@"Searching: %d", i);
            Node* node = [self.outlineView itemAtRow:i];

            if([self isSafeItemMatchesSearchCriteria:node recurse:NO]) {
                //NSLog(@"Found: %@", node.title);
                [self.outlineView selectRowIndexes: [NSIndexSet indexSetWithIndex: i] byExtendingSelection: NO];
                break;
            }
        }
    }
    else {
        // Search cleared - can we maintain the selection?
        
        [self selectItem:currentSelection];
    }
}

- (IBAction)onToggleShowHideQuickViewPassword:(id)sender {
    self.showPassword = !self.showPassword;
    [self showOrHideQuickViewPassword];
}

- (void)showOrHideQuickViewPassword {
    self.labelHiddenPassword.hidden = self.showPassword;
    self.labelPassword.hidden = !self.showPassword;
    self.imageViewTogglePassword.image = [NSImage imageNamed:self.showPassword ? @"hide" : @"show"];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

-(void)copyToPasteboard:(NSString*)text item:(Node*)item {
    if(!item || !text.length) {
        [[NSPasteboard generalPasteboard] clearContents];
        return;
    }
    
    NSString* deref = [self.model dereference:text node:item];
    
    [[NSPasteboard generalPasteboard] clearContents];
    [[NSPasteboard generalPasteboard] setString:deref forType:NSStringPboardType];
}

- (IBAction)onCopyTitle:(id)sender {
    [self copyTitle:[self getCurrentSelectedItem]];
}

- (IBAction)onCopyUsername:(id)sender {
    [self copyUsername:[self getCurrentSelectedItem]];
}

- (IBAction)onCopyEmail:(id)sender {
    [self copyEmail:[self getCurrentSelectedItem]];
}

- (IBAction)onCopyUrl:(id)sender {
    [self copyUrl:[self getCurrentSelectedItem]];
}

- (IBAction)onCopyPasswordAndLaunchUrl:(id)sender {
    Node* item = [self getCurrentSelectedItem];
    [self copyPassword:item];
    [self onLaunchUrl:sender];
}

- (IBAction)onCopyNotes:(id)sender {
    [self copyNotes:[self getCurrentSelectedItem]];
}

- (IBAction)onCopyPassword:(id)sender {
    [self copyPassword:[self getCurrentSelectedItem]];
}

- (IBAction)onCopyTotp:(id)sender {
    [self copyTotp:[self getCurrentSelectedItem]];
}

- (void)onDoubleClickCustomField:(id)sender {
    NSInteger row = self.customFieldsTable.clickedRow;
    if(row == -1) {
        return;
    }
    
    CustomField *field = self.customFields[row];
    [self copyCustomField:field];
}

- (IBAction)onCopyCustomFieldValue:(id)sender {
    NSInteger row = self.customFieldsTable.selectedRow;
    if(row == -1) {
        return;
    }
    
    CustomField *field = self.customFields[row];
    [self copyCustomField:field];
}

-(void)copyCustomField:(CustomField*)field {
    [[NSPasteboard generalPasteboard] clearContents];
    [[NSPasteboard generalPasteboard] setString:field.value forType:NSStringPboardType];
    
    [self showPopupToastNotification:[NSString stringWithFormat:@"'%@' Custom Field Copied", field.key]];
}

- (void)copyTitle:(Node*)item {
    if(!item) return;
    
    [self copyToPasteboard:item.title item:item];
    [self showPopupToastNotification:[NSString stringWithFormat:@"'%@' Title Copied", item.title]];
}

- (void)copyUsername:(Node*)item {
    if(!item) return;
    
    [self copyToPasteboard:item.fields.username item:item];
    [self showPopupToastNotification:[NSString stringWithFormat:@"'%@' Username Copied", item.title]];
}

- (void)copyEmail:(Node*)item {
    if(!item) return;
    
    [self copyToPasteboard:item.fields.email item:item];
    [self showPopupToastNotification:[NSString stringWithFormat:@"'%@' Email Copied", item.title]];
}

- (void)copyUrl:(Node*)item {
    if(!item) return;
    
    [self copyToPasteboard:item.fields.url item:item];
    [self showPopupToastNotification:[NSString stringWithFormat:@"'%@' URL Copied", item.title]];
}

- (void)copyNotes:(Node*)item {
    if(!item) return;
    
    [self copyToPasteboard:item.fields.notes item:item];
    [self showPopupToastNotification:[NSString stringWithFormat:@"'%@' Notes Copied", item.title]];
}

- (void)copyPassword:(Node*)item {
    if(!item || item.isGroup) {
        return;
    }

    [[NSPasteboard generalPasteboard] clearContents];
    
    NSString *password = [self.model dereference:item.fields.password node:item];
    [[NSPasteboard generalPasteboard] setString:password forType:NSStringPboardType];

    [self showPopupToastNotification:[NSString stringWithFormat:@"'%@' Password Copied", item.title]];
}

- (void)copyTotp:(Node*)item {
    if(!item || !item.otpToken) {
        return;
    }
    
    [[NSPasteboard generalPasteboard] clearContents];
    NSString *password = item.otpToken.password;
    [[NSPasteboard generalPasteboard] setString:password forType:NSStringPboardType];

    [self showPopupToastNotification:[NSString stringWithFormat:@"'%@' TOTP Copied", item.title]];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (Node*)getCurrentSelectedItem {
    NSInteger selectedRow = [self.outlineView selectedRow];
    
    //NSLog(@"Selected Row: %ld", (long)selectedRow);
    
    return [self.outlineView itemAtRow:selectedRow];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)expandParentsOfItem:(Node*)item {
    NSMutableArray *stack = [[NSMutableArray alloc] init];
    
    while (item.parent != nil) {
        item = item.parent;
        
        //NSLog(@"Got Parent == %@", i.title);
        
        [stack addObject:item];
    }
    
    while ([stack count]) {
        Node *group = [stack lastObject];
        
        //NSLog(@"Expanding %@", group.title);
        [self.outlineView expandItem:group];
        
        [stack removeObject:group];
    }
}

- (NSInteger)findRowForItemExpandIfNecessary:(id)item {
    NSInteger itemIndex = [self.outlineView rowForItem:item];
    
    if (itemIndex < 0) {
        [self expandParentsOfItem: item];
        
        itemIndex = [self.outlineView rowForItem:item];
        
        if (itemIndex < 0) {
            return itemIndex;
        }
    }
    
    return itemIndex;
}
                   
- (void)selectItem:(Node*)item {
    if(item) {
        NSInteger row = [self findRowForItemExpandIfNecessary:item];
        
        if(row >= 0) {
            [self.outlineView selectRowIndexes: [NSIndexSet indexSetWithIndex: row] byExtendingSelection: NO];
        }
        else {
            NSLog(@"Could not find item row for selection to maintain");
        }
    }
}

- (void)enableDragDrop {
    [self.outlineView registerForDraggedTypes:@[kDragAndDropUti]];
}

- (BOOL)outlineView:(NSOutlineView *)outlineView writeItems:(NSArray *)items toPasteboard:(NSPasteboard *)pasteboard {
    [pasteboard declareTypes:@[kDragAndDropUti] owner:self];

    NSArray<Node*> *nodes = items;
    NSArray* serializationIds = [nodes map:^id _Nonnull(Node * _Nonnull obj, NSUInteger idx) {
        return [obj getSerializationId:self.model.format != kPasswordSafe];
    }];
    
    [pasteboard setPropertyList:serializationIds forType:kDragAndDropUti];
    
    return YES;
}

- (NSDragOperation)outlineView:(NSOutlineView *)outlineView validateDrop:(id<NSDraggingInfo>)info
                  proposedItem:(id)item
            proposedChildIndex:(NSInteger)index
{
    // Only support internal drags (i.e. moves) - TODO: Allow inter safe movement?
    if ([info draggingSource] != self.outlineView) {
        return NSDragOperationNone;
    }
    
    NSArray<NSString*>* serializationIds = [info.draggingPasteboard propertyListForType:kDragAndDropUti];
    NSArray<Node*>* sourceItems = [serializationIds map:^id _Nonnull(NSString * _Nonnull obj, NSUInteger idx) {
        return [self.model getItemFromSerializationId:obj];
    }];
    
    Node* destinationItem = (item == nil) ? self.model.rootGroup : item;

    BOOL notValid = [sourceItems anyMatch:^BOOL(Node * _Nonnull obj) {
        BOOL valid = !destinationItem ||
                    (destinationItem.isGroup && [self.model validateChangeParent:destinationItem node:obj]);

        return !valid;
    }];
    
    //NSLog(@"%@ -> %d", item ? ((Node*)item).title : @"ROOT", !notValid);

    return !notValid ? NSDragOperationMove : NSDragOperationNone;
}

-(BOOL)outlineView:(NSOutlineView *)outlineView acceptDrop:(id<NSDraggingInfo>)info
              item:(id)item
        childIndex:(NSInteger)index {
    NSArray<NSString*>* serializationIds = [info.draggingPasteboard propertyListForType:kDragAndDropUti];
    NSArray<Node*>* sourceItems = [serializationIds map:^id _Nonnull(NSString * _Nonnull obj, NSUInteger idx) {
        return [self.model getItemFromSerializationId:obj];
    }];
    
    Node* destinationItem = (item == nil) ? self.model.rootGroup : item;

    for (Node* sourceItem in sourceItems) {
        BOOL result = [self.model changeParent:destinationItem node:sourceItem];
        NSLog(@"move: [%@] - success: [%d]", [sourceItem getSerializationId:self.model.format != kPasswordSafe], result);
    }
    
    return YES;
}

- (IBAction)onCreateRecord:(id)sender {
    Node *item = [self getCurrentSelectedItem];
    Node *parent = item && item.isGroup ? item : (item ? item.parent : self.model.rootGroup);

    if(![self.model addNewRecord:parent]) {
        [Alerts info:@"You cannot create a new record here. It must be within an existing folder." window:self.view.window];
        return;
    }
}

- (IBAction)onCreateGroup:(id)sender {
    Node *item = [self getCurrentSelectedItem];
    Node *parent = item && item.isGroup ? item : (item ? item.parent : self.model.rootGroup);
    
    NSString* title = [[[Alerts alloc] init] input:@"Please enter a Title for your new Group" defaultValue:kDefaultNewTitle allowEmpty:NO];
    
    if(title.length) {
        [self.model addNewGroup:parent title:title];
    }
}

- (void)onNewItemAdded:(Node*)node newRecord:(BOOL)newRecord {
    self.itemsCache = nil; // Clear items cache
    self.searchField.stringValue = @""; // Clear any ongoing search...
    [self.outlineView reloadData];
    NSInteger row = [self findRowForItemExpandIfNecessary:node];
    
    if(row < 0) {
        NSLog(@"Could not find newly added item?");
    }
    else {
        [self.outlineView selectRowIndexes: [NSIndexSet indexSetWithIndex: row] byExtendingSelection: NO];
    }

    if(newRecord) {
        [self openItemDetails:node newEntry:YES];
    }
}

- (IBAction)onDelete:(id)sender {
    NSIndexSet *rows = [self.outlineView selectedRowIndexes];

    if(rows.count == 1) {
        Node *item = [self getCurrentSelectedItem];
        if(!item) {
            return;
        }
        BOOL willRecycle = [self.model deleteWillRecycle:item];
        [Alerts yesNo:[NSString stringWithFormat:willRecycle ? @"Are you sure you want to send '%@' to the Recycle Bin?" : @"Are you sure you want to delete '%@'?", item.title] window:self.view.window completion:^(BOOL yesNo) {
            if(yesNo) {
                if(![self.model deleteItem:item]) {
                    [Alerts info:@"There was a problem trying to delete this item." window:self.view.window];
                }
            }
        }];
    }
    else {
        BOOL willRecycle = self.model.recycleBinEnabled;        
        [Alerts yesNo:[NSString stringWithFormat:willRecycle ? @"Are you sure you want to send %lu items to the Recycle Bin?" : @"Are you sure you want to delete %lu items?", (unsigned long)rows.count]
               window:self.view.window
           completion:^(BOOL yesNo) {
            if(yesNo) {
                [rows enumerateIndexesUsingBlock:^(NSUInteger idx, BOOL *stop) {
                    Node* node = [self.outlineView itemAtRow:idx];
                    [self.model deleteItem:node];
                }];
            }
        }];
    }
}

- (IBAction)onLaunchUrl:(id)sender {
    Node* item = [self getCurrentSelectedItem];
    
    NSString *urlString = [self.model dereference:item.fields.url node:item];
    
    if (!urlString.length) {
        return;
    }
    
    if (![urlString.lowercaseString hasPrefix:@"http://"] &&
        ![urlString.lowercaseString hasPrefix:@"https://"]) {
        urlString = [NSString stringWithFormat:@"http://%@", urlString];
    }
    
    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:urlString]];
}

- (IBAction)onCopyDiagnosticDump:(id)sender {
    [[NSPasteboard generalPasteboard] clearContents];
    
    NSString *dump = [self.model description];
    
    [[NSPasteboard generalPasteboard] setString:dump forType:NSStringPboardType];
}

- (BOOL)validateUserInterfaceItem:(id <NSValidatedUserInterfaceItem>)anItem
{
    SEL theAction = [anItem action];
    
    Node* item = [self getCurrentSelectedItem];
    
    if (theAction == @selector(onViewItemDetails:)) {
        return item != nil && !item.isGroup;
    }
    else if (theAction == @selector(onDelete:)) {
        if(self.outlineView.selectedRowIndexes.count > 1) {
            NSMenuItem* mi = (NSMenuItem*)anItem;
            [mi setTitle:@"Delete Items"];
        }
        else {
            NSMenuItem* mi = (NSMenuItem*)anItem;
            [mi setTitle:@"Delete Item"];
        }
        return item != nil;
    }
    else if(theAction == @selector(onCreateGroup:) ||
            theAction == @selector(onCreateRecord:)) {
        return self.model && !self.model.locked;
    }
    else if (theAction == @selector(onChangeMasterPassword:) ||
             theAction == @selector(onCopyAsCsv:) ||
             theAction == @selector(onCopyDiagnosticDump:) ||
             theAction == @selector(onImportFromCsvFile:) ||
             theAction == @selector(onLock:)) {
        return self.model && !self.model.locked;
    }
    else if (theAction == @selector(onShowSafeSummary:)) {
        return self.model && !self.model.locked;
    }
    else if (theAction == @selector(onFind:)) {
        return self.model && !self.model.locked &&
        ([Settings sharedInstance].fullVersion || [Settings sharedInstance].freeTrial);
    }
    else if(theAction == @selector(onLaunchUrl:) ||
            theAction == @selector(onCopyUrl:)) {
        return item && !item.isGroup;
    }
    else if (theAction == @selector(onCopyTitle:)) {
        return item && !item.isGroup;
    }
    else if (theAction == @selector(onCopyUsername:)) {
        return item && !item.isGroup;
    }
    else if (theAction == @selector(onCopyEmail:)) {
        return item && !item.isGroup && self.model.format == kPasswordSafe;
    }
    else if (theAction == @selector(onCopyPasswordAndLaunchUrl:)) {
        return item && !item.isGroup && item.fields.password.length;
    }
    else if (theAction == @selector(onCopyPassword:)) {
        return item && !item.isGroup && item.fields.password.length;
    }
    else if (theAction == @selector(onCopyTotp:)) {
        return item && !item.isGroup && item.otpToken;
    }
    else if (theAction == @selector(onCopyNotes:)) {
        return item && !item.isGroup && self.textViewNotes.textStorage.string.length; // TODO: Group can have notes
    }
    else if (theAction == @selector(onClearTouchId:)) {
        SafeMetaData* metaData = [self getDatabaseMetaData];
        return metaData != nil && BiometricIdHelper.sharedInstance.biometricIdAvailable;
    }
    else if (theAction == @selector(saveDocument:)) {
        return !self.model.locked;
    }
    else if (theAction == @selector(onSetItemIcon:)) {
        return item != nil && self.model.format != kPasswordSafe;
    }
    else if(theAction == @selector(onSetTotp:)) {
        return item && !item.isGroup;
    }
    else if(theAction == @selector(onClearTotp:)) {
        return item && !item.isGroup && item.otpToken;
    }
    else if (theAction == @selector(onViewItemHistory:)) {
        return
            item != nil &&
            !item.isGroup &&
            item.fields.keePassHistory.count > 0 &&
            (self.model.format == kKeePass || self.model.format == kKeePass4);
    }
    else if(theAction == @selector(onOutlineHeaderColumnsChanged:)) {
        NSMenuItem* menuItem = (NSMenuItem*)anItem;
        menuItem.state = [self isColumnVisible:menuItem.identifier];
        return [self isColumnAvailableForModel:menuItem.identifier];
    }
    
    return YES;
}

- (IBAction)onClearTouchId:(id)sender {
    SafeMetaData* metaData = [self getDatabaseMetaData];
    
    if(metaData) {
        [SafesList.sharedInstance remove:metaData.uuid];

        metaData.touchIdKeyFileDigest = nil;
        metaData.touchIdPassword = nil;
    }
}

- (IBAction)onCopyAsCsv:(id)sender {
    [[NSPasteboard generalPasteboard] clearContents];
    
    NSString *newStr = [[NSString alloc] initWithData:[Csv getSafeAsCsv:self.model.rootGroup] encoding:NSUTF8StringEncoding];
    
    [[NSPasteboard generalPasteboard] setString:newStr forType:NSStringPboardType];
}

- (NSURL*)getFileThroughFileOpenDialog
{  
    NSOpenPanel * panel = [NSOpenPanel openPanel];
    [panel setTitle:@"Choose CSV file to Import"];
    [panel setAllowsMultipleSelection:NO];
    [panel setCanChooseDirectories:NO];
    [panel setCanChooseFiles:YES];
    [panel setFloatingPanel:NO];
    [panel setDirectoryURL:[NSURL fileURLWithPath:NSHomeDirectory()]];
     panel.allowedFileTypes = @[@"csv"];

    NSInteger result = [panel runModal];
    if(result == NSModalResponseOK)
    {
        return [[panel URLs] firstObject];
    }
    
    return nil;
}

- (IBAction)onImportFromCsvFile:(id)sender {
    NSString* message = [NSString stringWithFormat:@"The CSV file must contain a header row with at least one of the following fields:\n\n[%@, %@, %@, %@, %@, %@]\n\nThe order of the fields doesn't matter.", kCSVHeaderTitle, kCSVHeaderUsername, kCSVHeaderEmail, kCSVHeaderPassword, kCSVHeaderUrl, kCSVHeaderNotes];
   
    [Alerts info:@"CSV Format" informativeText:message window:self.view.window completion:^{
        dispatch_async(dispatch_get_main_queue(), ^{[self importFromCsvFile];});
    }];
}

- (void)importFromCsvFile {
    NSURL* url = [self getFileThroughFileOpenDialog];
        
    if(url) {
        NSError *error = nil;
        NSArray *rows = [NSArray arrayWithContentsOfCSVURL:url options:CHCSVParserOptionsSanitizesFields | CHCSVParserOptionsUsesFirstLineAsKeys];
        
        if (rows == nil) {
            //something went wrong; log the error and exit
            NSLog(@"error parsing file: %@", error);
            [Alerts error:error window:self.view.window];
            return;
        }
        else if(rows.count == 0){
            [Alerts info:@"CSV File Contains Zero Rows. Cannot Import." window:self.view.window];
        }
        else {
            CHCSVOrderedDictionary *firstRow = [rows firstObject];
            
            if([firstRow objectForKey:kCSVHeaderTitle] ||
               [firstRow objectForKey:kCSVHeaderUsername] ||
               [firstRow objectForKey:kCSVHeaderUrl] ||
               [firstRow objectForKey:kCSVHeaderEmail] ||
               [firstRow objectForKey:kCSVHeaderPassword] ||
               [firstRow objectForKey:kCSVHeaderNotes]) {
                NSString* message = [NSString stringWithFormat:@"Found %lu valid rows in CSV file. Are you sure you would like to import now?", (unsigned long)rows.count];
                
                [Alerts yesNo:message window:self.view.window completion:^(BOOL yesNo) {
                    if(yesNo) {
                        [self.model importRecordsFromCsvRows:rows];
                        
                        [Alerts info:@"CSV File Successfully Imported." window:self.view.window];
                    }
                }];
            }
            else {
                [Alerts info:@"No valid rows found. Ensure CSV file contains a header row and at least one of the required fields." window:self.view.window];
            }
        }
    }
}

- (NSString *)formatDate:(NSDate *)date {
    if (!date) {
        return @"<Unknown>";
    }
    
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    
    dateFormatter.dateStyle = NSDateFormatterMediumStyle;
    dateFormatter.timeStyle = NSDateFormatterShortStyle;
    dateFormatter.locale = [NSLocale currentLocale];
    
    NSString *dateString = [dateFormatter stringFromDate:date];
    
    return dateString;
}

- (IBAction)onPasswordPreferences:(id)sender {
    [PreferencesWindowController.sharedInstance showOnTab:1];
}

- (void)onPreferencesChanged:(NSNotification*)notification {
    NSLog(@"Preferences Have Changed Notification Received... Refreshing View.");

    dispatch_async(dispatch_get_main_queue(), ^{
        Node* currentSelection = [self getCurrentSelectedItem];
        
        self.itemsCache = nil; // Clear items cache
        
        [self bindColumnsToSettings];
        [self customizeOutlineView];
        
        [self.outlineView reloadData];
        
        [self selectItem:currentSelection];
    });
}

static BasicOrderedDictionary* getSummaryDictionary(ViewModel* model) {
    BasicOrderedDictionary *ret = [[BasicOrderedDictionary alloc] init];
    
    for (NSString* key in [model.metadata kvpForUi].allKeys) {
        NSString *value = [[model.metadata kvpForUi] objectForKey:key];
        [ret addKey:key andValue:value];
    }
    
    [ret addKey:@"Unique Usernames" andValue:[NSString stringWithFormat:@"%lu", (unsigned long)model.usernameSet.count]];
    [ret addKey:@"Unique Passwords" andValue:[NSString stringWithFormat:@"%lu", (unsigned long)model.passwordSet.count]];
    [ret addKey:@"Most Popular Username" andValue:model.mostPopularUsername ? model.mostPopularUsername : @"<None>"];
    [ret addKey:@"Number of Entries" andValue:[NSString stringWithFormat:@"%lu", (unsigned long)model.numberOfRecords]];
    [ret addKey:@"Number of Folders" andValue:[NSString stringWithFormat:@"%lu", (unsigned long)model.numberOfGroups]];
    
    return ret;
}

- (IBAction)onShowSafeSummary:(id)sender {
    [self.outlineView deselectAll:nil]; // Funky side effect, no selection -> show safe summary
}

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView {
    if (tableView == self.tableViewSummary) {
        BasicOrderedDictionary* dictionary = getSummaryDictionary(self.model);
        return dictionary.count;
    }
    else {
        return self.customFields.count;
    }
}

- (NSView *)tableView:(NSTableView *)tableView viewForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row {
    if(tableView == self.tableViewSummary) {
        NSTableCellView* cell = [self.tableViewSummary makeViewWithIdentifier:@"KeyCellIdentifier" owner:nil];

        BasicOrderedDictionary *dict = getSummaryDictionary(self.model);
        
        NSString *key = dict.allKeys[row];
        NSString *value = [dict objectForKey:key];
        
        value = value == nil ? @"" : value; // Safety Only
        
        cell.textField.stringValue = [tableColumn.identifier isEqualToString:@"KeyColumn"] ? key : value;
        
        return cell;
    }
    else  {
        BOOL isKeyColumn = [tableColumn.identifier isEqualToString:@"CustomFieldKeyColumn"];
        NSString* cellId = isKeyColumn ? @"CustomFieldKeyCellIdentifier" : @"CustomFieldValueCellIdentifier";
        
        CustomField* field = [self.customFields objectAtIndex:row];
        
        if(isKeyColumn) {
            NSTableCellView* cell = [self.customFieldsTable makeViewWithIdentifier:cellId owner:nil];
            cell.textField.stringValue = field.key;
            return cell;
        }
        else {
            CustomFieldTableCellView* cell = [self.customFieldsTable makeViewWithIdentifier:cellId owner:nil];
            
            cell.value = field.value;
            cell.protected = field.protected && !(field.value.length == 0 && !Settings.sharedInstance.concealEmptyProtectedFields);
            cell.valueHidden = field.protected && !(field.value.length == 0 && !Settings.sharedInstance.concealEmptyProtectedFields); // Initially Hide the Value if it is protected
            
            return cell;
        }
    }
}

- (IBAction)onSetItemIcon:(id)sender {
    Node *item = [self getCurrentSelectedItem];
    
    if(!item) {
        return;
    }
    
    [self onEditNodeIcon:item];
}

- (void)onEditNodeIcon:(Node*)item {
    if(self.model.format == kPasswordSafe) {
        return;
    }
    
    __weak ViewController* weakSelf = self;
    self.selectPredefinedIconController = [[SelectPredefinedIconController alloc] initWithWindowNibName:@"SelectPredefinedIconController"];
    self.selectPredefinedIconController.customIcons = self.model.customIcons;
    self.selectPredefinedIconController.hideSelectFile = self.model.format == kKeePass1;
    self.selectPredefinedIconController.onSelectedItem = ^(NSNumber * _Nullable index, NSData * _Nullable data, NSUUID * _Nullable existingCustom) {
        onSelectedNewIcon(weakSelf.model, item, index, data, existingCustom, weakSelf.view.window);
    };
    
    [self.view.window beginSheet:self.selectPredefinedIconController.window  completionHandler:nil];
}

void onSelectedNewIcon(ViewModel* model, Node* item, NSNumber* index, NSData* data, NSUUID* existingCustom, NSWindow* window) {
    if(data) {
        NSImage* icon = [[NSImage alloc] initWithData:data];
        if(icon) {
            if(data.length > kMaxRecommendCustomIconSize) {
                NSImage* rescaled = scaleImage(icon, CGSizeMake(kMaxCustomIconDimension, kMaxCustomIconDimension));
                CGImageRef cgRef = [rescaled CGImageForProposedRect:NULL context:nil hints:nil];
                NSBitmapImageRep *newRep = [[NSBitmapImageRep alloc] initWithCGImage:cgRef];
                NSData *compressed = [newRep representationUsingType:NSBitmapImageFileTypePNG properties:@{ }];
                NSInteger saving = data.length - compressed.length;
                if(saving < 0) {
                    NSLog(@"Not much saving from PNG trying JPG...");
                    compressed = [newRep representationUsingType:NSBitmapImageFileTypeJPEG properties:@{ }];
                    saving = data.length - compressed.length;
                }
                
                if(saving > (32 * 1024)) {
                    NSString* savingStr = [[[NSByteCountFormatter alloc] init] stringFromByteCount:saving];
                    NSString* message = [NSString stringWithFormat:@"This is a large image to use as an icon. Would you like to use a scaled down version to save %@?", savingStr];
                    [Alerts yesNo:message window:window completion:^(BOOL yesNo) {
                        if(yesNo) {
                            [model setItemIcon:item index:index existingCustom:existingCustom custom:compressed];
                        }
                        else {
                            [model setItemIcon:item index:index existingCustom:existingCustom custom:data];
                        }
                    }];
                }
                else {
                    [model setItemIcon:item index:index existingCustom:existingCustom custom:data];
                }
            }
            else {
                [model setItemIcon:item index:index existingCustom:existingCustom custom:data];
            }
        }
        else {
            [Alerts info:@"This is not a valid image file." window:window];
        }
    }
    else {
        [model setItemIcon:item index:index existingCustom:existingCustom custom:nil];
    }
}

- (IBAction)onViewItemHistory:(id)sender {
    Node *item = [self getCurrentSelectedItem];
    
    if(item == nil ||
       item.isGroup || item.fields.keePassHistory.count == 0 ||
       (!(self.model.format == kKeePass || self.model.format == kKeePass4))) {
        return;
    }
    
    self.keePassHistoryController = [[MacKeePassHistoryController alloc] initWithWindowNibName:@"KeePassHistoryController"];

    __weak ViewController* weakSelf = self;
    self.keePassHistoryController.onDeleteHistoryItem = ^(Node * _Nonnull node) {
        [weakSelf.model deleteHistoryItem:item historicalItem:node];
    };
    self.keePassHistoryController.onRestoreHistoryItem = ^(Node * _Nonnull node) {
        [weakSelf.model restoreHistoryItem:item historicalItem:node];
    };
    
    self.keePassHistoryController.model = self.model;
    self.keePassHistoryController.history = item.fields.keePassHistory; 
    
    [self.view.window beginSheet:self.keePassHistoryController.window completionHandler:nil];
}

- (IBAction)refreshOtpCode:(id)sender {
    if([self isColumnVisible:kTOTPColumn]) {
        NSScrollView* scrollView = [self.outlineView enclosingScrollView];
        CGRect visibleRect = scrollView.contentView.visibleRect;
        NSRange rowRange = [self.outlineView rowsInRect:visibleRect];
        NSInteger totpColumnIndex = [self.outlineView columnWithIdentifier:kTOTPColumn];

        if(rowRange.length) {
            [self.outlineView beginUpdates];
            for(int i=0;i<rowRange.length;i++) {
                Node* item = (Node*)[self.outlineView itemAtRow:rowRange.location + i];
                if(item.otpToken) {
                    [self.outlineView reloadDataForRowIndexes:[NSIndexSet indexSetWithIndex:rowRange.location + i]
                                                columnIndexes:[NSIndexSet indexSetWithIndex:totpColumnIndex]];

                }
            }
            [self.outlineView endUpdates];
        }
    }
    
    [self refreshQuickViewOtpCode];
}

- (void)refreshQuickViewOtpCode {
    Node *item = [self getCurrentSelectedItem];
    if(item == nil || item.isGroup) {
        return;
    }
    
    if(!Settings.sharedInstance.doNotShowTotp && item.otpToken) {
        self.totpRow.hidden = NO;
        
        //NSLog(@"Token: [%@] - Password: %@", item.otpToken, item.otpToken.password);
        
        self.textFieldTotp.stringValue = item.otpToken.password;
        
        uint64_t remainingSeconds = [self getTotpRemainingSeconds:item];
        
        self.textFieldTotp.textColor = (remainingSeconds < 5) ? NSColor.redColor : (remainingSeconds < 9) ? NSColor.orangeColor : NSColor.controlTextColor;

        self.progressTotp.minValue = 0;
        self.progressTotp.maxValue = item.otpToken.period;
        self.progressTotp.doubleValue = remainingSeconds;
    }
    else {
        self.totpRow.hidden = YES;
        self.textFieldTotp.stringValue = @"000000";
    }
}

- (uint64_t)getTotpRemainingSeconds:(Node*)item {
    return item.otpToken.period - ((uint64_t)([NSDate date].timeIntervalSince1970) % (uint64_t)item.otpToken.period);
}
- (IBAction)onSetTotp:(id)sender {
    Node *item = [self getCurrentSelectedItem];
    
    if(item == nil || item.isGroup) {
        return;
    }
    
    NSString* response = [[Alerts alloc] input:@"Please enter the secret or an OTPAuth URL" defaultValue:@"" allowEmpty:NO];
    
    if(response) {
        [self.model setTotp:item otp:response];
    }
}

- (IBAction)onClearTotp:(id)sender {
    Node *item = [self getCurrentSelectedItem];
    
    if(item == nil || item.isGroup || !item.otpToken) {
        return;
    }
    
    [self.model clearTotp:item];
}

- (void)showPopupToastNotification:(NSString*)message {
    if(Settings.sharedInstance.doNotShowChangeNotifications) {
        return;
    }
    
    MBProgressHUD *hud = [MBProgressHUD showHUDAddedTo:self.view animated:YES];
    hud.labelText = message;
    hud.color = [NSColor colorWithDeviceRed:0.23 green:0.5 blue:0.82 alpha:0.60];
    hud.mode = MBProgressHUDModeText;
    hud.margin = 10.f;
    hud.yOffset = 150.f;
    hud.removeFromSuperViewOnHide = YES;
    hud.dismissible = YES;
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [hud hide:YES];
    });
}

- (IBAction)onShowHideQuickView:(id)sender {
    Settings.sharedInstance.revealDetailsImmediately = !Settings.sharedInstance.revealDetailsImmediately;
    self.quickViewColumn.hidden = !Settings.sharedInstance.revealDetailsImmediately;
    [self bindQuickViewButton];
}

- (void)bindQuickViewButton {
    [self.buttonToggleQuickViewPanel setTitle:self.quickViewColumn.hidden ? @"Show Quick View Panel" : @"Hide Quick View Panel"];
}

- (IBAction)onCollapseAll:(id)sender {
    [self.outlineView collapseItem:nil collapseChildren:YES];
}

- (IBAction)onExpandAll:(id)sender {
    [self.outlineView expandItem:nil expandChildren:YES];
}

@end


// FUTURE: Attempt to fix funky tab ordering! Very difficult

//- (void)controlTextDidEndEditing:(NSNotification *)notification {
////    NSLog(@"controlTextDidEndEditing - XXX");
//
//    NSDictionary *userInfo = [notification userInfo];
//
//    int textMovement = [[userInfo valueForKey:@"NSTextMovement"] intValue];
//
//    //[self.outlineView controlTextDidEndEditing:notification];
//
//    NSInteger editedColumn = [self.outlineView columnForView:notification.object];
//    NSInteger editedRow = [self.outlineView rowForView:notification.object];
//
//    NSInteger lastCol = self.outlineView.numberOfColumns; // [[self.outlineView tableColumns] count] - 1;
//    NSInteger lastRow = self.outlineView.numberOfRows; // [[self.outlineView tableColumns] count] - 1;
//
//    if (textMovement == NSTabTextMovement)
//    {
//        if (editedColumn != lastCol - 1 )
//        {
//            [self.outlineView selectRowIndexes:[NSIndexSet indexSetWithIndex:editedRow] byExtendingSelection:NO];
//            [self.outlineView editColumn: editedColumn+1 row: editedRow withEvent: nil select: YES];
//        }
//        else
//        {
//            if (editedRow !=lastRow-1)
//            {
//                [self.outlineView editColumn:0 row:editedRow + 1 withEvent:nil select:YES];
//            }
//            else
//            {
//                [self.outlineView editColumn:0 row:0 withEvent:nil select:YES]; // Go to the first cell
//            }
//        }
//    }
//    else if (textMovement == NSReturnTextMovement)
//    {
//        if(editedRow !=lastRow-1)
//        {
//            [self.outlineView selectRowIndexes:[NSIndexSet indexSetWithIndex:editedRow+1] byExtendingSelection:NO];
//            [self.outlineView editColumn: editedColumn row: editedRow+1 withEvent: nil select: YES];
//        }
//        else
//        {
//            if (editedColumn !=lastCol - 1)
//            {
//                [self.outlineView editColumn:editedColumn+1 row:0 withEvent:nil select:YES];
//            }
//            else
//            {
//                [self.outlineView editColumn:0 row:0 withEvent:nil select:YES]; //Go to the first cell
//            }
//        }
//    }
//
//
//
//
//
//    //    if ( (editedColumn == lastColumn)
////        && (textMovement == NSTextMovementTab)
////        && editedRow < ([self.outlineView numberOfRows] - 1)
////        )
////    {
////        // the tab key was hit while in the last column,
////        // so go to the left most cell in the next row
////        [self.outlineView selectRowIndexes:[NSIndexSet indexSetWithIndex:(editedRow+1)] byExtendingSelection:NO];
////        [self.outlineView editColumn: 0 row: (editedRow + 1)  withEvent: nil select: YES];
////    }
//
