//
//  OpenSafeView.m
//  StrongBox
//
//  Created by Mark McGuill on 06/06/2014.
//  Copyright (c) 2014 Mark McGuill. All rights reserved.
//

#import "BrowseSafeView.h"
#import "PwSafeSerialization.h"
#import "SelectDestinationGroupController.h"
#import <MessageUI/MessageUI.h>
#import "RecordView.h"
#import "Alerts.h"
#import <ISMessages/ISMessages.h>
#import "Settings.h"
#import "SafeDetailsView.h"
#import "NSArray+Extensions.h"
#import "Utils.h"
#import "NodeIconHelper.h"
#import "Node+OTPToken.h"
#import "OTPToken+Generation.h"
#import "SetNodeIconUiHelper.h"
#import "ItemDetailsViewController.h"
#import "BrowseItemCell.h"
#import "MasterDetailViewController.h"
#import "BrowsePreferencesTableViewController.h"
#import "SortOrderTableViewController.h"

static NSString* const kBrowseItemCell = @"BrowseItemCell";

@interface BrowseSafeView () <MFMailComposeViewControllerDelegate, UISearchBarDelegate, UISearchResultsUpdating>

@property (strong, nonatomic) NSArray<Node*> *searchResults;
@property (strong, nonatomic) NSArray<Node*> *items;
@property (strong, nonatomic) UISearchController *searchController;
@property (strong, nonatomic) UIBarButtonItem *savedOriginalNavButton;
@property (strong, nonatomic) UILongPressGestureRecognizer *longPressRecognizer;

@property (nonatomic) NSInteger tapCount;
@property (nonatomic) NSIndexPath *tappedIndexPath;
@property (strong, nonatomic) NSTimer *tapTimer;

@property NSTimer* timerRefreshOtp;
@property (strong) SetNodeIconUiHelper* sni; // Required: Or Delegate does not work!

@property NSMutableArray<NSArray<NSNumber*>*>* reorderItemOperations;
@property BOOL sortOrderForAutomaticSortDuringEditing;

@property BOOL hasAlreadyAppeared;

@property (weak, nonatomic) IBOutlet UIBarButtonItem *closeBarButton;
@property (weak, nonatomic) IBOutlet UIBarButtonItem *buttonViewPreferences;

@end

@implementation BrowseSafeView

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:YES];
    
    if(!self.hasAlreadyAppeared && Settings.sharedInstance.immediateSearchOnBrowse && self.currentGroup == self.viewModel.database.rootGroup) {
        dispatch_async(dispatch_get_main_queue(), ^(void) {
            [self.searchController.searchBar becomeFirstResponder];
        });
    }
    self.hasAlreadyAppeared = YES;
    
    self.navigationController.toolbarHidden = NO;
    self.navigationController.toolbar.hidden = NO;
    [self refreshItems];
    [self updateDetailsView:nil];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    
    if(self.timerRefreshOtp) {
        [self.timerRefreshOtp invalidate];
        self.timerRefreshOtp = nil;
    }
}

- (IBAction)updateOtpCodes:(id)sender {
    if(![self.tableView isEditing]) { // DO not update during edit, cancels left swipe menu and edit selections!
        NSArray<NSIndexPath*>* visible = [self.tableView indexPathsForVisibleRows];
        
        NSArray<Node*> *nodes = [self getDataSource];
        NSArray* visibleOtpRows = [visible filter:^BOOL(NSIndexPath * _Nonnull obj) {
            return nodes[obj.row].otpToken != nil;
        }];
        
        [self.tableView reloadRowsAtIndexPaths:visibleOtpRows withRowAnimation:UITableViewRowAnimationNone];
    }
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    [self setupTableview];
    
    [self setupTips];
    
    [self setupNavBar];
    
    NSMutableArray* rightBarButtons = [self.navigationItem.rightBarButtonItems mutableCopy];
    [rightBarButtons insertObject:self.editButtonItem atIndex:0];
    self.navigationItem.rightBarButtonItems = rightBarButtons;

//    self.navigationItem.leftBarButtonItem = self.editButtonItem;
    
    [self setupSearchBar];
    
    [self refreshItems];
    
    if(self.splitViewController) {
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(showDetailTargetDidChange:) name:UIViewControllerShowDetailTargetDidChangeNotification object:self.splitViewController];
    }
}

- (void)showDetailTargetDidChange:(NSNotification *)notification{
    NSLog(@"showDetailTargetDidChange");
    if(!self.splitViewController.isCollapsed) {
        NSIndexPath *ip = [self.tableView indexPathForSelectedRow];
        if(ip) {
            Node* item = [self getDataSource][ip.row];
            [self updateDetailsView:item];
        }
        else{
            dispatch_async(dispatch_get_main_queue(), ^{
                [self updateDetailsView:nil];
            });
        }
    }
}

- (void)updateDetailsView:(Node*)item {
    if(self.splitViewController) {
        if(item) {
            if(item.isGroup) {
                [self performSegueWithIdentifier:@"sequeToSubgroup" sender:item];
            }
            else{
                [self performSegueWithIdentifier:@"segueMasterDetailToDetail" sender:item];
            }
        }
        else if(!self.splitViewController.isCollapsed) {
            [self performSegueWithIdentifier:@"segueMasterDetailToEmptyDetail" sender:nil];
        }
    }
}

- (void)setupNavBar {
    if(self.splitViewController) {
        if(self.currentGroup != self.viewModel.database.rootGroup) {
            self.closeBarButton.enabled = NO;
            [self.closeBarButton setTintColor:UIColor.clearColor];
        }
    }
    else {
        self.closeBarButton.enabled = NO;
        [self.closeBarButton setTintColor:UIColor.clearColor];
    }
    self.navigationItem.leftItemsSupplementBackButton = YES;

    self.navigationItem.title = [NSString stringWithFormat:@"%@%@%@",
                                 (self.currentGroup.parent == nil) ?
                                 self.viewModel.metadata.nickName : self.currentGroup.title,
                                 self.viewModel.isUsingOfflineCache ? @" (Offline)" : @"",
                                 self.viewModel.isReadOnly ? @" (Read Only)" : @""];
    
    if (@available(iOS 11.0, *)) {
        self.navigationController.navigationBar.prefersLargeTitles = NO;
    }
    self.navigationController.toolbarHidden = NO;
    self.navigationController.toolbar.hidden = NO;
    [self.navigationController setNavigationBarHidden:NO];
    self.navigationController.navigationBar.hidden = NO;
    self.navigationController.navigationBarHidden = NO;
}

- (void)setupSearchBar {
    self.extendedLayoutIncludesOpaqueBars = YES;
    self.definesPresentationContext = YES;
    
    self.searchController = [[UISearchController alloc] initWithSearchResultsController:nil];
    self.searchController.searchResultsUpdater = self;
    self.searchController.dimsBackgroundDuringPresentation = NO;
    self.searchController.searchBar.delegate = self;
    self.searchController.searchBar.scopeButtonTitles = @[@"Title", @"Username", @"Password", @"URL", @"All Fields"];
    self.searchController.searchBar.selectedScopeButtonIndex = kSearchScopeAll;
    
    if ([[Settings sharedInstance] isProOrFreeTrial]) {
        if (@available(iOS 11.0, *)) {
            self.navigationItem.searchController = self.searchController;
            
            // We want the search bar visible immediately for Root
            
            self.navigationItem.hidesSearchBarWhenScrolling = self.currentGroup != self.viewModel.database.rootGroup;
        } else {
            self.tableView.tableHeaderView = self.searchController.searchBar;
            [self.searchController.searchBar sizeToFit];
        }
    }
    
    [self.searchController setActive:NO];
}

- (void)setupTips {
    if(Settings.sharedInstance.hideTips) {
        self.navigationItem.prompt = nil;
    }
    
    if (!Settings.sharedInstance.hideTips && (!self.currentGroup || self.currentGroup.parent == nil)) {
        if(arc4random_uniform(100) < 50) {
            [ISMessages showCardAlertWithTitle:@"Fast Password Copy"
                                       message:@"Tap and hold entry for fast password copy"
                                      duration:2.5f
                                   hideOnSwipe:YES
                                     hideOnTap:YES
                                     alertType:ISAlertTypeSuccess
                                 alertPosition:ISAlertPositionBottom
                                       didHide:nil];
        }
        else {
            [ISMessages showCardAlertWithTitle:@"Fast Username Copy"
                                       message:@"Double Tap for fast username copy"
                                      duration:2.5f
                                   hideOnSwipe:YES
                                     hideOnTap:YES
                                     alertType:ISAlertTypeSuccess
                                 alertPosition:ISAlertPositionBottom
                                       didHide:nil];
        }
    }
}

- (void)setupTableview {
    [self.tableView registerNib:[UINib nibWithNibName:kBrowseItemCell bundle:nil] forCellReuseIdentifier:kBrowseItemCell];
    
    self.longPressRecognizer = [[UILongPressGestureRecognizer alloc]
                                initWithTarget:self
                                action:@selector(handleLongPress:)];
    self.longPressRecognizer.minimumPressDuration = 1;
    self.longPressRecognizer.cancelsTouchesInView = YES;
    
    [self.tableView addGestureRecognizer:self.longPressRecognizer];
    
    self.tableView.allowsMultipleSelection = NO;
    self.tableView.allowsMultipleSelectionDuringEditing = YES;
    self.tableView.allowsSelectionDuringEditing = YES;
    
    self.tableView.estimatedRowHeight = UITableViewAutomaticDimension;
    self.tableView.rowHeight = UITableViewAutomaticDimension;
    self.tableView.tableFooterView = [UIView new];
    
    self.clearsSelectionOnViewWillAppear = YES;
}

- (IBAction)onClose:(id)sender {
    MasterDetailViewController* master = (MasterDetailViewController*)self.splitViewController;
    [master onClose];
}

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    return !self.viewModel.isUsingOfflineCache && !self.viewModel.isReadOnly;
}

- (BOOL)tableView:(UITableView *)tableView canMoveRowAtIndexPath:(NSIndexPath *)indexPath
{
    return self.viewModel.database.format != kPasswordSafe && Settings.sharedInstance.browseSortField == kBrowseSortFieldNone; 
}

- (void)tableView:(UITableView *)tableView moveRowAtIndexPath:(NSIndexPath *)sourceIndexPath toIndexPath:(NSIndexPath *)destinationIndexPath {
    if(![sourceIndexPath isEqual:destinationIndexPath]) {
        NSLog(@"Move Row at %@ to %@", sourceIndexPath, destinationIndexPath);
        
        if(self.reorderItemOperations == nil) {
            self.reorderItemOperations = [NSMutableArray array];
        }
        [self.reorderItemOperations addObject:@[@(sourceIndexPath.row), @(destinationIndexPath.row)]];

        [self enableDisableToolbarButtons]; // Disable moving/deletion if there's been a move
    }
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    return UITableViewAutomaticDimension;  // Required for iOS 9 and 10
}

- (CGFloat)tableView:(UITableView *)tableView estimatedHeightForRowAtIndexPath:(NSIndexPath *)indexPath {
    return 60.0f; // Required for iOS 9 and 10
}

- (IBAction)onSortItems:(id)sender {
    if(self.isEditing) {
        [Alerts yesNo:self
                title:@"Sort Items By Title?"
              message:@"Do you want to sort all the items in this folder by Title? This will set the order in which they are stored in your database." action:^(BOOL response) {
            if(response) {
                self.reorderItemOperations = nil; // Discard existing reordering ops...
                self.sortOrderForAutomaticSortDuringEditing = !self.sortOrderForAutomaticSortDuringEditing;
                [self.currentGroup sortChildren:self.sortOrderForAutomaticSortDuringEditing];
                [self saveChangesToSafeAndRefreshView];
            }
        }];
    }
    else {
        [self performSegueWithIdentifier:@"segueToSortOrder" sender:nil];
    }
}

- (void)addHistoricalNode:(Node*)item originalNodeForHistory:(Node*)originalNodeForHistory {
    BOOL shouldAddHistory = YES; // FUTURE: Config on/off? only valid for KeePass 2+ also...
    if(shouldAddHistory && originalNodeForHistory != nil) {
        [item.fields.keePassHistory addObject:originalNodeForHistory];
    }
}

- (void)onRenameItem:(NSIndexPath * _Nonnull)indexPath {
    Node *item = [[self getDataSource] objectAtIndex:indexPath.row];
    
    [Alerts OkCancelWithTextField:self
                    textFieldText:item.title
                            title:@"Rename Item"
                          message:@"Please enter a new title for this item"
                       completion:^(NSString *text, BOOL response) {
                           if(response && [text length]) {
                               if(!item.isGroup) {
                                   Node* originalNodeForHistory = [item cloneForHistory];
                                   [self addHistoricalNode:item originalNodeForHistory:originalNodeForHistory];
                               }
                               
                               item.fields.accessed = [NSDate date];
                               item.fields.modified = [NSDate date];
                               
                               [item setTitle:text allowDuplicateGroupTitles:self.viewModel.database.format != kPasswordSafe];
                               
                               [self saveChangesToSafeAndRefreshView];
                           }
                       }];
}

- (void)onDeleteSingleItem:(NSIndexPath * _Nonnull)indexPath {
    Node *item = [[self getDataSource] objectAtIndex:indexPath.row];
    BOOL willRecycle = [self.viewModel deleteWillRecycle:item];

    [Alerts yesNo:self.searchController.isActive ? self.searchController : self
            title:@"Are you sure?"
          message:[NSString stringWithFormat:willRecycle ? @"Are you sure you want to send '%@' to the Recycle Bin?" : @"Are you sure you want to permanently delete '%@'?", [self dereference:item.title node:item]]
           action:^(BOOL response) {
               if (response) {
                   if(![self.viewModel deleteItem:item]) {
                       [Alerts warn:self title:@"Delete Failed" message:@"There was an error trying to delete this item."];
                   }
                   else {
                       [self saveChangesToSafeAndRefreshView];
                   }
               }
           }];
}

- (void)onSetIconForItem:(NSIndexPath * _Nonnull)indexPath {
    Node *item = [[self getDataSource] objectAtIndex:indexPath.row];

    self.sni = [[SetNodeIconUiHelper alloc] init];
    self.sni.customIcons = self.viewModel.database.customIcons;
    
    NSString* urlHint;
    if(!item.isGroup) {
        urlHint = item.fields.url;
        if(!urlHint.length) {
            urlHint = item.title;
        }
    }    
    
    [self.sni changeIcon:self
                 urlHint:urlHint
                  format:self.viewModel.database.format
              completion:^(BOOL goNoGo, NSNumber * userSelectedNewIconIndex, NSUUID * userSelectedExistingCustomIconId, UIImage * userSelectedNewCustomIcon) {
        NSLog(@"completion: %d - %@-%@-%@", goNoGo, userSelectedNewIconIndex, userSelectedExistingCustomIconId, userSelectedNewCustomIcon);
        if(goNoGo) {
            if(!item.isGroup) {
                Node* originalNodeForHistory = [item cloneForHistory];
                [self addHistoricalNode:item originalNodeForHistory:originalNodeForHistory];
            }
            
            item.fields.accessed = [NSDate date];
            item.fields.modified = [NSDate date];
            
            if(userSelectedNewCustomIcon) {
                NSData *data = UIImagePNGRepresentation(userSelectedNewCustomIcon);
                [self.viewModel.database setNodeCustomIcon:item data:data];
            }
            else if(userSelectedExistingCustomIconId) {
                item.customIconUuid = userSelectedExistingCustomIconId;
            }
            else if(userSelectedNewIconIndex) {
                if(userSelectedNewIconIndex.intValue == -1) {
                    item.iconId = !item.isGroup ? @(0) : @(48); // Default
                }
                else {
                    item.iconId = userSelectedNewIconIndex;
                }
                item.customIconUuid = nil;
            }
            
            [self saveChangesToSafeAndRefreshView];
        }
    }];
}

- (nullable NSArray<UITableViewRowAction *> *)tableView:(UITableView *)tableView editActionsForRowAtIndexPath:(nonnull NSIndexPath *)indexPath {
    UITableViewRowAction *removeAction = [UITableViewRowAction rowActionWithStyle:UITableViewRowActionStyleDestructive title:@"Delete" handler:^(UITableViewRowAction * _Nonnull action, NSIndexPath * _Nonnull indexPath) {
        [self onDeleteSingleItem:indexPath];
    }];
    
    UITableViewRowAction *renameAction = [UITableViewRowAction rowActionWithStyle:UITableViewRowActionStyleNormal title:@"Rename" handler:^(UITableViewRowAction * _Nonnull action, NSIndexPath * _Nonnull indexPath) {
        [self onRenameItem:indexPath];
    }];
    renameAction.backgroundColor = UIColor.blueColor;
    
    UITableViewRowAction *setIconAction = [UITableViewRowAction rowActionWithStyle:UITableViewRowActionStyleNormal title:@"Set Icon" handler:^(UITableViewRowAction * _Nonnull action, NSIndexPath * _Nonnull indexPath) {
        [self onSetIconForItem:indexPath];
    }];
    
    setIconAction.backgroundColor = UIColor.purpleColor;

    return self.viewModel.database.format != kPasswordSafe ? @[removeAction, renameAction, setIconAction] : @[removeAction, renameAction];
}

- (BOOL)shouldPerformSegueWithIdentifier:(NSString *)identifier sender:(id)sender {
    //ignore segue from cell since we we are calling manually in didSelectRowAtIndexPath
    return !self.isEditing && (sender == self || [identifier isEqualToString:@"segueToSafeSettings"]);
}

- (NSArray<Node *> *)getDataSource {
    return (self.searchController.isActive ? self.searchResults : self.items);
}

- (void)updateSearchResultsForSearchController:(UISearchController *)searchController {
    self.searchResults = [self.viewModel.database search:searchController.searchBar.text
                                                   scope:searchController.searchBar.selectedScopeButtonIndex
                                             dereference:Settings.sharedInstance.searchDereferencedFields
                                   includeKeePass1Backup:Settings.sharedInstance.showKeePass1BackupGroup
                                       includeRecycleBin:Settings.sharedInstance.showRecycleBinInSearchResults];

    [self.tableView reloadData];
    [self startOtpRefreshTimerIfAppropriate];
}

- (void)searchBar:(UISearchBar *)searchBar selectedScopeButtonIndexDidChange:(NSInteger)selectedScope {
    [self updateSearchResultsForSearchController:self.searchController];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return [self getDataSource].count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    Node *node = [self getDataSource][indexPath.row];
    BrowseItemCell* cell = [self.tableView dequeueReusableCellWithIdentifier:kBrowseItemCell forIndexPath:indexPath];

    NSString* title = Settings.sharedInstance.viewDereferencedFields ? [self dereference:node.title node:node] : node.title;
    UIImage* icon = [NodeIconHelper getIconForNode:node database:self.viewModel.database];
    NSString *groupLocation = self.searchController.isActive ? [self getGroupPathDisplayString:node] : @"";

    if(node.isGroup) {
        BOOL italic = (self.viewModel.database.recycleBinEnabled && node == self.viewModel.database.recycleBinNode);

        NSString* childCount = Settings.sharedInstance.showChildCountOnFolderInBrowse ? [NSString stringWithFormat:@"(%lu)", (unsigned long)node.children.count] : @"";
        
        [cell setGroup:title icon:icon childCount:childCount italic:italic groupLocation:groupLocation tintColor:self.viewModel.database.format == kPasswordSafe ? [NodeIconHelper folderTintColor] : nil];
    }
    else {
        NSString* subtitle = [self.viewModel.database getBrowseItemSubtitle:node];        
        NSString* flags = node.fields.attachments.count > 0 ? @"📎" : @"";
        flags = Settings.sharedInstance.showFlagsInBrowse ? flags : @"";
        
        [cell setRecord:title subtitle:subtitle icon:icon groupLocation:groupLocation flags:flags];

        [self setOtpCellProperties:cell node:node];
    }
    
    return cell;
}

- (NSString*)dereference:(NSString*)text node:(Node*)node {
    return [self.viewModel.database dereference:text node:node];
}

- (void)setOtpCellProperties:(BrowseItemCell*)cell node:(Node*)node {
    if(!Settings.sharedInstance.hideTotpInBrowse && node.otpToken) {
        uint64_t remainingSeconds = node.otpToken.period - ((uint64_t)([NSDate date].timeIntervalSince1970) % (uint64_t)node.otpToken.period);
        
        cell.otpLabel.text = [NSString stringWithFormat:@"%@", node.otpToken.password];
        cell.otpLabel.textColor = (remainingSeconds < 5) ? [UIColor redColor] : (remainingSeconds < 9) ? [UIColor orangeColor] : [UIColor blueColor];
        cell.otpLabel.alpha = 1;
        
        if(remainingSeconds < 16) {
            [UIView animateWithDuration:0.45 delay:0.0 options:UIViewAnimationOptionRepeat | UIViewAnimationOptionAutoreverse animations:^{
                cell.otpLabel.alpha = 0.5;
            } completion:nil];
        }
    }
    else {
        cell.otpLabel.text = @"";
    }
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    if(self.tapCount == 2 && self.tapTimer != nil && [self.tappedIndexPath isEqual:indexPath]) {
        [self.tapTimer invalidate];
        self.tapTimer = nil;
        self.tapCount = 0;
        self.tappedIndexPath = nil;
        
        [self handleTripleTap:indexPath];
    }
    else if(self.tapCount == 1 && self.tapTimer != nil && [self.tappedIndexPath isEqual:indexPath]){
        [self.tapTimer invalidate];
        self.tapCount = self.tapCount + 1;
        self.tapTimer = [NSTimer scheduledTimerWithTimeInterval:0.2 target:self selector:@selector(tapTimerFired:) userInfo:nil repeats:NO];
    }
    else if(self.tapCount == 0) {
        //This is the first tap. If there is no tap till tapTimer is fired, it is a single tap
        self.tapCount = self.tapCount + 1;
        self.tappedIndexPath = indexPath;
        self.tapTimer = [NSTimer scheduledTimerWithTimeInterval:0.2 target:self selector:@selector(tapTimerFired:) userInfo:nil repeats:NO];
    }
    else if(![self.tappedIndexPath isEqual:indexPath]){
        //tap on new row
        self.tapCount = 0;
        self.tappedIndexPath = indexPath;
        if(self.tapTimer != nil){
            [self.tapTimer invalidate];
            self.tapTimer = nil;
        }
    }
}

- (void)tapTimerFired:(NSTimer *)aTimer{
    if(self.tapCount == 1) {
        [self tapOnCell:self.tappedIndexPath];
    }
    else if(self.tapCount == 2) {
        [self handleDoubleTap:self.tappedIndexPath];
    }
    
    self.tapCount = 0;
    self.tappedIndexPath = nil;
    self.tapTimer = nil;
}

- (void)tapOnCell:(NSIndexPath *)indexPath  {
    if (!self.editing) {
        NSArray* arr = [self getDataSource];
        
        if(indexPath.row >= arr.count) {
            return;
        }
        
        Node *item = arr[indexPath.row];

        [self.tableView deselectRowAtIndexPath:indexPath animated:YES];

        if(self.splitViewController) {
            [self updateDetailsView:item];
        }
        else {
            if (!item.isGroup) {
                if (@available(iOS 11.0, *)) {
                    [self performSegueWithIdentifier:@"segueToItemDetails" sender:item];
                }
                else {
                    [self performSegueWithIdentifier:@"segueToRecord" sender:item];
                }
            }
            else {
                [self performSegueWithIdentifier:@"sequeToSubgroup" sender:item];
            }
        }
    }
    else {
        [self enableDisableToolbarButtons];
    }
}

- (void)enableDisableToolbarButtons {
    BOOL ro = self.viewModel.isUsingOfflineCache || self.viewModel.isReadOnly;
    
    self.buttonAddRecord.enabled = !ro && !self.isEditing && self.currentGroup.childRecordsAllowed;
    self.buttonSafeSettings.enabled = !self.isEditing;
    self.buttonViewPreferences.enabled = !self.isEditing;
    
    self.buttonMove.enabled = (!ro && self.isEditing && self.tableView.indexPathsForSelectedRows.count > 0 && self.reorderItemOperations.count == 0);
    self.buttonDelete.enabled = !ro && self.isEditing && self.tableView.indexPathsForSelectedRows.count > 0 && self.reorderItemOperations.count == 0;
    
    self.buttonSortItems.enabled = !self.isEditing ||
        (!ro && self.isEditing && self.viewModel.database.format != kPasswordSafe && Settings.sharedInstance.browseSortField == kBrowseSortFieldNone);
    
    UIImage* sortImage = self.isEditing ? [UIImage imageNamed:self.sortOrderForAutomaticSortDuringEditing ? @"sort-32-descending" : @"sort-32"] : [UIImage imageNamed:Settings.sharedInstance.browseSortOrderDescending ? @"sort-descending" : @"sort-ascending"];
    
    [self.buttonSortItems setImage:sortImage];
        
    self.buttonAddGroup.enabled = !ro && !self.isEditing;
}

- (NSArray<Node*>*)getItems {
    NSArray<Node*>* ret = self.currentGroup.children;
    
    if(self.viewModel.database.format == kKeePass1 && !Settings.sharedInstance.showKeePass1BackupGroup) {
        Node* backupGroup = self.viewModel.database.keePass1BackupNode;
        
        if(backupGroup) {
            if([self.currentGroup contains:backupGroup]) {
                ret = [self.currentGroup.children filter:^BOOL(Node * _Nonnull obj) {
                    return obj != backupGroup;
                }];
            }
        }
    }
    else if(self.viewModel.database.format == kKeePass || self.viewModel.database.format == kKeePass4) {
        Node* recycleBin = self.viewModel.database.recycleBinNode;
        
        if(Settings.sharedInstance.doNotShowRecycleBinInBrowse && recycleBin) {
            if([self.currentGroup contains:recycleBin]) {
                ret = [self.currentGroup.children filter:^BOOL(Node * _Nonnull obj) {
                    return obj != recycleBin;
                }];
            }
        }
    }
    
    return [self.viewModel.database sortItemsForBrowse:ret];
}

- (void)refreshItems {
    self.items = [self getItems];
    
    // Display
    
    if(self.searchController.isActive) {
        [self updateSearchResultsForSearchController:self.searchController];
    }
    else {
        [self.tableView reloadData];
    }
    
    self.editButtonItem.enabled = (!self.viewModel.isUsingOfflineCache &&
                                   !self.viewModel.isReadOnly &&
                                   [self getDataSource].count > 0);
    
    [self enableDisableToolbarButtons];
    
    // Any OTPs we should start a refresh timer if so...
    
    [self startOtpRefreshTimerIfAppropriate];
}

- (void)startOtpRefreshTimerIfAppropriate {
    if(self.timerRefreshOtp) {
        [self.timerRefreshOtp invalidate];
        self.timerRefreshOtp = nil;
    }
    
    BOOL hasOtpToken = [[self getDataSource] anyMatch:^BOOL(Node * _Nonnull obj) {
        return obj.otpToken != nil;
    }];
    
    if(!Settings.sharedInstance.hideTotpInBrowse && hasOtpToken) {
        NSLog(@"Starting OTP Refresh Timer");
        
        self.timerRefreshOtp = [NSTimer timerWithTimeInterval:1.0f target:self selector:@selector(updateOtpCodes:) userInfo:nil repeats:YES];
        [[NSRunLoop mainRunLoop] addTimer:self.timerRefreshOtp forMode:NSRunLoopCommonModes];
    }
}

- (NSString *)getGroupPathDisplayString:(Node *)vm {
    return [NSString stringWithFormat:@"(in %@)", [self.viewModel.database getSearchParentGroupPathDisplayString:vm]];
}

- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    if ([segue.identifier isEqualToString:@"segueToRecord"]) {
        Node *record = (Node *)sender;
        RecordView *vc = segue.destinationViewController;
        vc.record = record;
        vc.parentGroup = self.currentGroup;
        vc.viewModel = self.viewModel;
    }
    else if ([segue.identifier isEqualToString:@"segueToItemDetails"]) {
        Node *record = (Node *)sender;

        ItemDetailsViewController *vc = segue.destinationViewController;
        
        vc.createNewItem = record == nil;
        vc.item = record;
        vc.parentGroup = self.currentGroup;
        vc.readOnly = self.viewModel.isReadOnly || self.viewModel.isUsingOfflineCache;
        vc.databaseModel = self.viewModel;
        vc.onChanged = ^{
            [self refreshItems];
        };
    }
    else if ([segue.identifier isEqualToString:@"segueMasterDetailToDetail"]) {
        Node *record = (Node *)sender;
        
        UINavigationController* nav = segue.destinationViewController;
        ItemDetailsViewController *vc = (ItemDetailsViewController*)nav.topViewController;
        
        vc.createNewItem = record == nil;
        vc.item = record;
        vc.parentGroup = self.currentGroup;
        vc.readOnly = self.viewModel.isReadOnly || self.viewModel.isUsingOfflineCache;
        vc.databaseModel = self.viewModel;
        vc.onChanged = ^{
            [self refreshItems];
        };
    }
    else if ([segue.identifier isEqualToString:@"sequeToSubgroup"]){
        BrowseSafeView *vc = segue.destinationViewController;
        vc.currentGroup = (Node *)sender;
        vc.viewModel = self.viewModel;
    }
    else if ([segue.identifier isEqualToString:@"segueToSelectDestination"])
    {
        NSArray *itemsToMove = (NSArray *)sender;
        
        UINavigationController *nav = segue.destinationViewController;
        SelectDestinationGroupController *vc = (SelectDestinationGroupController*)nav.topViewController;
        
        vc.currentGroup = self.viewModel.database.rootGroup;
        vc.viewModel = self.viewModel;
        vc.itemsToMove = itemsToMove;
        vc.onDone = ^{
            [self dismissViewControllerAnimated:YES completion:^{
                [self refreshItems];
            }];
        };
    }
    else if ([segue.identifier isEqualToString:@"segueToSafeSettings"])
    {
        UINavigationController* nav = segue.destinationViewController;
        SafeDetailsView *vc = (SafeDetailsView *)nav.topViewController;
        vc.viewModel = self.viewModel;
    }
    else if([segue.identifier isEqualToString:@"segueToViewSettings"]) {
        UINavigationController* nav = segue.destinationViewController;
        BrowsePreferencesTableViewController* vc = (BrowsePreferencesTableViewController*)nav.topViewController;
        vc.format = self.viewModel.database.format;
        vc.onPreferencesChanged = ^{
            [self refreshItems];
        };
    }
    else if([segue.identifier isEqualToString:@"segueToSortOrder"]){
        UINavigationController* nav = segue.destinationViewController;
        SortOrderTableViewController* vc = (SortOrderTableViewController*)nav.topViewController;
        vc.format = self.viewModel.database.format;
        vc.field = Settings.sharedInstance.browseSortField;
        vc.descending = Settings.sharedInstance.browseSortOrderDescending;
        vc.foldersSeparately = Settings.sharedInstance.browseSortFoldersSeparately;
        
        vc.onChangedOrder = ^(BrowseSortField field, BOOL descending, BOOL foldersSeparately) {
            Settings.sharedInstance.browseSortField = field;
            Settings.sharedInstance.browseSortOrderDescending = descending;
            Settings.sharedInstance.browseSortFoldersSeparately = foldersSeparately;
            [self refreshItems];
        };
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (IBAction)onAddGroup:(id)sender {
    [Alerts OkCancelWithTextField:self
             textFieldPlaceHolder:@"Group Name"
                            title:@"Enter Group Name"
                          message:@"Please Enter the New Group Name:"
                       completion:^(NSString *text, BOOL response) {
                           if (response) {
                               if ([self.viewModel addNewGroup:self.currentGroup title:text] != nil) {
                                   [self saveChangesToSafeAndRefreshView];
                               }
                               else {
                                   [Alerts warn:self title:@"Cannot create group" message:@"Could not create a group with this name here, possibly because one with this name already exists."];
                               }
                           }
                       }];
}

- (IBAction)onAddRecord:(id)sender {
    if (@available(iOS 11.0, *)) {
        if(self.splitViewController) {
            [self performSegueWithIdentifier:@"segueMasterDetailToDetail" sender:nil];
        }
        else {
            [self performSegueWithIdentifier:@"segueToItemDetails" sender:nil];
        }
    }
    else {
        [self performSegueWithIdentifier:@"segueToRecord" sender:nil];
    }
}

- (IBAction)onMove:(id)sender {
    if(self.editing) {
        NSArray *selectedRows = (self.tableView).indexPathsForSelectedRows;
        
        if (selectedRows.count > 0) {
            NSArray<Node *> *itemsToMove = [self getSelectedItems:selectedRows];
            
            [self performSegueWithIdentifier:@"segueToSelectDestination" sender:itemsToMove];
            
            [self setEditing:NO animated:YES];
        }
    }
}

- (IBAction)onDeleteToolbarButton:(id)sender {
    NSArray *selectedRows = (self.tableView).indexPathsForSelectedRows;
    
    if (selectedRows.count > 0) {
        NSArray<Node *> *items = [self getSelectedItems:selectedRows];
        Node* item = [items firstObject];
        BOOL willRecycle = [self.viewModel deleteWillRecycle:item];
        
        [Alerts yesNo:self.searchController.isActive ? self.searchController : self
                title:@"Are you sure?"
              message:willRecycle ? @"Are you sure you want to send these item(s) to the Recycle Bin?" : @"Are you sure you want to permanently delete these item(s)?"
               action:^(BOOL response) {
                   if (response) {
                       NSArray<Node *> *items = [self getSelectedItems:selectedRows];
                       
                       BOOL fail = NO;
                       for (Node* item in items) {
                           if(![self.viewModel deleteItem:item]) {
                               fail = YES;
                           }
                       }
                       
                       if(fail) {
                           [Alerts warn:self title:@"Error Deleting" message:@"There was a problem deleting a least one of these items."];
                       }
                       
                       [self saveChangesToSafeAndRefreshView];
                   }
               }];
    }
}

- (NSArray<Node*> *)getSelectedItems:(NSArray<NSIndexPath *> *)selectedRows {
    NSMutableIndexSet *indicesOfItems = [NSMutableIndexSet new];
    
    for (NSIndexPath *selectionIndex in selectedRows) {
        [indicesOfItems addIndex:selectionIndex.row];
    }
    
    NSArray *items = [[self getDataSource] objectsAtIndexes:indicesOfItems];
    return items;
}

- (void)saveChangesToSafeAndRefreshView {
    [self refreshItems];
    
    [self.viewModel update:^(NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^(void) {
            [self setEditing:NO animated:YES];
            
            [self refreshItems];
            
            [self updateDetailsView:nil];
            
            if (error) {
                [Alerts error:self title:@"Error Saving" error:error];
            }
        });
    }];
}

- (void)setEditing:(BOOL)editing animated:(BOOL)animate {
    [super setEditing:editing animated:animate];
    
    NSLog(@"setEditing: %d", editing);
    
    [self enableDisableToolbarButtons];
    
    //NSLog(@"setEditing: %hhd", editing);
    
    if (!editing) {
        self.navigationItem.leftBarButtonItem = self.savedOriginalNavButton;
        if(self.reorderItemOperations) {
            // Do the reordering
            NSLog(@"Reordering");
            
            for (NSArray<NSNumber*>* moveOp in self.reorderItemOperations) {
                NSUInteger src = moveOp[0].unsignedIntegerValue;
                NSUInteger dest = moveOp[1].unsignedIntegerValue;
                NSLog(@"Move: %lu -> %lu", (unsigned long)src, (unsigned long)dest);
                [self.currentGroup moveChild:src to:dest];
            }
            
            self.reorderItemOperations = nil;
            [self saveChangesToSafeAndRefreshView];
        }
    }
    else {
        self.reorderItemOperations = nil;
        
        UIBarButtonItem *cancelButton = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemCancel
                                                                                      target:self
                                                                                      action:@selector(cancelEditing)];
        
        self.savedOriginalNavButton = self.navigationItem.leftBarButtonItem;
        self.navigationItem.leftBarButtonItem = cancelButton;
    }
}

- (void)cancelEditing {
    self.reorderItemOperations = nil;
    [self setEditing:false];
}

- (void)handleTripleTap:(NSIndexPath *)indexPath {
    Node *item = [self getDataSource][indexPath.row];
    
    if (item.isGroup) {
        NSLog(@"Item is group, cannot Fast Username Copy...");
        
        [self performSegueWithIdentifier:@"sequeToSubgroup" sender:item];
        
        return;
    }
 
    if(!item.otpToken) { // No TOTP - Treat this as a double tap
        [self handleDoubleTap:indexPath];
    }
    else {
        UIPasteboard *pasteboard = [UIPasteboard generalPasteboard];
        
        pasteboard.string = item.otpToken.password;
        
        [ISMessages showCardAlertWithTitle:[NSString stringWithFormat:@"%@ TOTP Copied", [self dereference:item.title node:item]]
                                   message:nil
                                  duration:3.f
                               hideOnSwipe:YES
                                 hideOnTap:YES
                                 alertType:ISAlertTypeSuccess
                             alertPosition:ISAlertPositionTop
                                   didHide:nil];
        
        NSLog(@"Fast TOTP Copy on %@", item.title);
        
        if(!self.isEditing) {
            [self.tableView deselectRowAtIndexPath:indexPath animated:YES];
        }
    }
}

- (void)handleDoubleTap:(NSIndexPath *)indexPath {
    Node *item = [self getDataSource][indexPath.row];
    
    if (item.isGroup) {
        NSLog(@"Item is group, cannot Fast Username Copy...");
        
        [self performSegueWithIdentifier:@"sequeToSubgroup" sender:item];
        
        return;
    }
    
    UIPasteboard *pasteboard = [UIPasteboard generalPasteboard];
    
    pasteboard.string = [self dereference:item.fields.username node:item];
    
    [ISMessages showCardAlertWithTitle:[NSString stringWithFormat:@"%@ Username Copied", [self dereference:item.title node:item]]
                               message:nil
                              duration:3.f
                           hideOnSwipe:YES
                             hideOnTap:YES
                             alertType:ISAlertTypeSuccess
                         alertPosition:ISAlertPositionTop
                               didHide:nil];
    
    NSLog(@"Fast Username Copy on %@", item.title);

    if(!self.isEditing) {
        [self.tableView deselectRowAtIndexPath:indexPath animated:YES];
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Long Press

- (void)handleLongPress:(UILongPressGestureRecognizer *)sender {
    if (sender.state != UIGestureRecognizerStateBegan) {
        return;
    }
    
    CGPoint tapLocation = [self.longPressRecognizer locationInView:self.tableView];
    NSIndexPath *indexPath = [self.tableView indexPathForRowAtPoint:tapLocation];
    
    if (!indexPath || indexPath.row >= [self getDataSource].count) {
        NSLog(@"Not on a cell");
        return;
    }
    
    Node *item = [self getDataSource][indexPath.row];
    
    if (item.isGroup) {
        NSLog(@"Item is group, cannot Fast PW Copy...");
        return;
    }
    
    NSLog(@"Fast Password Copy on %@", item.title);
    
    [self copyPasswordOnLongPress:item withTapLocation:tapLocation];
}

- (void)copyPasswordOnLongPress:(Node *)item withTapLocation:(CGPoint)tapLocation {
    UIPasteboard *pasteboard = [UIPasteboard generalPasteboard];
    
    BOOL copyTotp = (item.fields.password.length == 0 && item.otpToken);
    pasteboard.string = copyTotp ? item.otpToken.password : [self dereference:item.fields.password node:item];
    
    [ISMessages showCardAlertWithTitle:[NSString stringWithFormat:copyTotp ? @"'%@' OTP Code Copied" : @"'%@' Password Copied", [self dereference:item.title node:item]]
                               message:nil
                              duration:3.f
                           hideOnSwipe:YES
                             hideOnTap:YES
                             alertType:ISAlertTypeSuccess
                         alertPosition:ISAlertPositionTop
                               didHide:nil];
}

- (IBAction)onViewPreferences:(id)sender {
    [self performSegueWithIdentifier:@"segueToViewSettings" sender:nil];
}

@end
