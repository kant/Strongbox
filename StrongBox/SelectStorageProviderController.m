//
//  SelectStorageProviderController.m
//  StrongBox
//
//  Created by Mark on 08/09/2017.
//  Copyright © 2017 Mark McGuill. All rights reserved.
//

#import "SelectStorageProviderController.h"
#import "LocalDeviceStorageProvider.h"
#import "GoogleDriveStorageProvider.h"
#import "DropboxV2StorageProvider.h"
#import "CustomStorageProviderTableViewCell.h"
#import "DatabaseModel.h"
#import "Alerts.h"
#import "StorageBrowserTableViewController.h"
#import "AppleICloudProvider.h"
#import "Settings.h"
#import "OneDriveStorageProvider.h"
#import "SFTPStorageProvider.h"
#import "WebDAVStorageProvider.h"
#import <MobileCoreServices/MobileCoreServices.h>

@interface SelectStorageProviderController () <UIDocumentPickerDelegate>

@property (nonatomic, copy, nonnull) NSArray<id<SafeStorageProvider>> *providers;

@end

@implementation SelectStorageProviderController

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    
    if(self.existing) {
        [self.navigationItem setPrompt:@"Select where your existing database is stored"];
    }
    else {
        [self.navigationItem setPrompt:@"Select where you would like to store your new database"];
    }

    self.navigationController.toolbar.hidden = YES;
    self.navigationController.toolbarHidden = YES;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    SFTPStorageProvider* sftpProviderWithFastListing = [[SFTPStorageProvider alloc] init];
    sftpProviderWithFastListing.maintainSessionForListing = YES;

    WebDAVStorageProvider* webDavProvider = [[WebDAVStorageProvider alloc] init];
    webDavProvider.maintainSessionForListings = YES;
    
    if(self.existing) {
        self.providers = @[[GoogleDriveStorageProvider sharedInstance],
                           [DropboxV2StorageProvider sharedInstance],
                           [OneDriveStorageProvider sharedInstance],
                           webDavProvider,
                           sftpProviderWithFastListing];
    }
    else {
        if ([Settings sharedInstance].iCloudOn) {
            self.providers = @[[AppleICloudProvider sharedInstance],
                               [GoogleDriveStorageProvider sharedInstance],
                               [DropboxV2StorageProvider sharedInstance],
                               [OneDriveStorageProvider sharedInstance],
                               webDavProvider,
                               sftpProviderWithFastListing,
                               [LocalDeviceStorageProvider sharedInstance]];
        }
        else {
            self.providers = @[[GoogleDriveStorageProvider sharedInstance],
                               [DropboxV2StorageProvider sharedInstance],
                               [OneDriveStorageProvider sharedInstance],
                               webDavProvider,
                               sftpProviderWithFastListing,
                               [LocalDeviceStorageProvider sharedInstance]];
        }
    }
    
    self.tableView.tableFooterView = [UIView new];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.providers.count + (self.existing ? 2 : 0);
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    CustomStorageProviderTableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"storageProviderReuseIdentifier" forIndexPath:indexPath];
    
    if(indexPath.row == self.providers.count) {
        cell.text.text = @"Copy from URL...";
        cell.image.image =  [UIImage imageNamed:@"Disconnect-32x32"];
    }
    else if(indexPath.row == self.providers.count + 1) {
        cell.text.text = @"Files...";
        cell.image.image =  [UIImage imageNamed:@"ios11-files-app-icon"];
    }
    else {
        id<SafeStorageProvider> provider = [self.providers objectAtIndex:indexPath.row];

        cell.text.text = provider.displayName;
        cell.image.image = [UIImage imageNamed:provider.icon];
    }
    
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    if(indexPath.row == self.providers.count) {
        [self initiateManualImportFromUrl];
    }
    else if(indexPath.row == self.providers.count + 1) {
        [self onAddThroughFilesApp];
    }
    else {
        id<SafeStorageProvider> provider = [_providers objectAtIndex:indexPath.row];
        if (provider.storageId == kLocalDevice && !self.existing) {
            [Alerts yesNo:self
                    title:@"Local Device Database Caveat"
                  message:@"Since a local database is only stored on this device, any loss of this device will lead to the loss of "
             "all passwords stored within this database. You may want to consider using a cloud storage provider, such as the ones "
             "supported by Strongbox to avoid catastrophic data loss.\n\nWould you still like to proceed with creating "
             "a local device database?"
                   action:^(BOOL response) {
                       if (response) {
                           [self segueToBrowserOrAdd:provider];
                       }
                       else {
                           [self.tableView deselectRowAtIndexPath:indexPath animated:YES];
                       }
                   }];
        }
        else {
            [self segueToBrowserOrAdd:provider];
        }
    }
}

- (void)initiateManualImportFromUrl {
    [Alerts OkCancelWithTextField:self
             textFieldPlaceHolder:@"URL"
                            title:@"Enter URL"
                          message:@"Please Enter the URL of the Database File."
                       completion:^(NSString *text, BOOL response) {
                           if (response) {
                               NSURL *url = [NSURL URLWithString:text];
                               NSLog(@"URL: %@", url);
                               
                               [self importFromManualUiUrl:url];
                           }
                       }];
}

- (void)onAddThroughFilesApp {
    UIDocumentPickerViewController *vc = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[(NSString*)kUTTypeItem] inMode:UIDocumentPickerModeOpen];
    vc.delegate = self;
    [self presentViewController:vc animated:YES completion:nil];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Three different methods of adding/creating

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSLog(@"didPickDocumentsAtURLs: %@", urls);
    
    NSURL* url = [urls objectAtIndex:0];
    
    self.onDone([SelectedStorageParameters parametersForFilesApp:url]);
}

- (void)importFromManualUiUrl:(NSURL *)importURL {
    NSError* error;
    NSData *importedData = [NSData dataWithContentsOfURL:importURL options:kNilOptions error:&error];
    
    if(error) {
        [Alerts error:self title:@"Error Reading from URL" error:error];
        return;
    }
    
    if (![DatabaseModel isAValidSafe:importedData error:&error]) {
        [Alerts error:self
                title:@"Invalid Database"
                error:error];
        
        return;
    }
    
    self.onDone([SelectedStorageParameters parametersForManualDownload:importedData]);
}

- (void)segueToBrowserOrAdd:(id<SafeStorageProvider>)provider {
    BOOL storageBrowseRequired = (self.existing && provider.browsableExisting) || (!self.existing && provider.browsableNew);

    if (storageBrowseRequired) {
        [self performSegueWithIdentifier:@"SegueToBrowser" sender:provider];
    }
    else {
        if(self.existing) {
            // How can we get here?! - I don't think this is possible
            self.onDone([SelectedStorageParameters parametersForNativeProviderExisting:provider file:nil likelyFormat:kFormatUnknown]);
        }
        else {
            self.onDone([SelectedStorageParameters parametersForNativeProviderCreate:provider folder:nil]);
        }
    }
}

- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    if ([segue.identifier isEqualToString:@"SegueToBrowser"]) {
        StorageBrowserTableViewController *vc = segue.destinationViewController;
        
        vc.existing = self.existing;
        vc.safeStorageProvider = sender;
        vc.parentFolder = nil;
        vc.onDone = self.onDone;
    }
}

- (IBAction)onCancel:(id)sender {
    self.onDone([SelectedStorageParameters userCancelled]);
}

@end
