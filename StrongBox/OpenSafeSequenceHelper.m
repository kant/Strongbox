//
//  OpenSafeSequenceHelper.m
//  Strongbox-iOS
//
//  Created by Mark on 12/10/2018.
//  Copyright © 2018 Mark McGuill. All rights reserved.
//

#import "OpenSafeSequenceHelper.h"
#import "Settings.h"
#import "IOsUtils.h"
#import <LocalAuthentication/LocalAuthentication.h>
#import "Alerts.h"
#import "SafeStorageProviderFactory.h"
#import "OfflineDetector.h"
#import <SVProgressHUD/SVProgressHUD.h>
#import <MobileCoreServices/MobileCoreServices.h>
#import "Utils.h"

#ifndef IS_APP_EXTENSION
#import "ISMessages/ISMessages.h"
#endif

typedef void(^CompletionBlock)(Model* model);
typedef void(^PasswordAndKeyFileCompletionBlock)(BOOL response);

@interface OpenSafeSequenceHelper () <UIDocumentPickerDelegate>

@property (nonatomic, strong) NSString* biometricIdName;
@property (nonatomic, strong) UIAlertController *alertController;
@property (nonnull) UIViewController* viewController;
@property (nonnull) SafeMetaData* safe;
@property BOOL askAboutTouchIdEnrolIfAppropriate;
@property BOOL openAutoFillCache;
@property (nonnull) CompletionBlock completion;
@property (nonnull) PasswordAndKeyFileCompletionBlock passwordAndKeyFileCompletionBlock;

@property BOOL isTouchIdOpen;
@property NSString* masterPassword;
@property NSData* keyFileDigest;

@end

@implementation OpenSafeSequenceHelper

+ (instancetype)sharedInstance {
    static OpenSafeSequenceHelper *sharedInstance = nil;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        sharedInstance = [[OpenSafeSequenceHelper alloc] init];
    });
    
    return sharedInstance;
}

- (instancetype)init {
    if(self = [super init]) {
        self.biometricIdName = [[Settings sharedInstance] getBiometricIdName];
    }
    
    return self;
}

- (void)beginOpenSafeSequence:(UIViewController*)viewController
                         safe:(SafeMetaData*)safe
askAboutTouchIdEnrolIfAppropriate:(BOOL)askAboutTouchIdEnrolIfAppropriate
                   completion:(void (^)(Model* model))completion {
    [self beginOpenSafeSequence:viewController
                           safe:safe
              openAutoFillCache:NO
askAboutTouchIdEnrolIfAppropriate:askAboutTouchIdEnrolIfAppropriate
                     completion:completion];
}

- (void)beginOpenSafeSequence:(UIViewController*)viewController
                         safe:(SafeMetaData*)safe
            openAutoFillCache:(BOOL)openAutoFillCache
askAboutTouchIdEnrolIfAppropriate:(BOOL)askAboutTouchIdEnrolIfAppropriate
                   completion:(void (^)(Model* model))completion {
    self.viewController = viewController;
    self.safe = safe;
    self.askAboutTouchIdEnrolIfAppropriate = askAboutTouchIdEnrolIfAppropriate;
    self.openAutoFillCache = openAutoFillCache;
    self.completion = completion;
    
    if (!Settings.sharedInstance.disallowAllBiometricId &&
        safe.isTouchIdEnabled &&
        [IOsUtils isTouchIDAvailable] &&
        safe.isEnrolledForTouchId &&
        ([[Settings sharedInstance] isProOrFreeTrial])) {
        [self showTouchIDAuthentication];
    }
    else {
        [self promptForSafePassword];
    }
}

- (void)showTouchIDAuthentication {
    LAContext *localAuthContext = [[LAContext alloc] init];
    localAuthContext.localizedFallbackTitle = @"Enter Master Password";
    
    [localAuthContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                     localizedReason:@"Identify to login"
                               reply:^(BOOL success, NSError *error) {
                                   [self  onTouchIdDone:success error:error];
                               } ];
}

- (void)onTouchIdDone:(BOOL)success
                error:(NSError *)error {
    if (success) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self.isTouchIdOpen = YES;
            self.masterPassword = self.safe.touchIdPassword;
            self.keyFileDigest = self.safe.touchIdKeyFileDigest;
            
            [self openSafe];
        });
    }
    else {
        if (error.code == LAErrorAuthenticationFailed) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [Alerts   warn:self.viewController
                         title:[NSString stringWithFormat:@"%@ Failed", self.biometricIdName]
                       message:[NSString stringWithFormat:@"%@ Authentication Failed. You must now enter your password manually to open the safe.", self.biometricIdName]
                    completion:^{
                        [self promptForSafePassword];
                    }];
            });
        }
        else if (error.code == LAErrorUserFallback)
        {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self promptForSafePassword];
            });
        }
        else if (error.code != LAErrorUserCancel)
        {
            dispatch_async(dispatch_get_main_queue(), ^{
                [Alerts   warn:self.viewController
                         title:[NSString stringWithFormat:@"%@ Failed", self.biometricIdName]
                       message:[NSString stringWithFormat:@"%@ has not been setup or system has cancelled. You must now enter your password manually to open the safe.", self.biometricIdName]
                    completion:^{
                        [self promptForSafePassword];
                    }];
            });
        }
    }
}

- (void)promptForSafePassword {
    self.passwordAndKeyFileCompletionBlock = ^(BOOL response) {
        NSLog(@"promptForPasswordAndOrKeyFile Done: %d", response);
        
        if (response) {
            self.isTouchIdOpen = NO;
            [self openSafe];
        }
        else {
            // TODO: Should we call completion?
        }
    };
    
    [self promptForPasswordAndOrKeyFile];
}

- (void)  openSafe {
    id <SafeStorageProvider> provider = [SafeStorageProviderFactory getStorageProviderFromProviderId:self.safe.storageProvider];
    
    if(self.openAutoFillCache) {
        [[LocalDeviceStorageProvider sharedInstance] readAutoFillCache:self.safe
                                                        viewController:self.viewController
                                                            completion:^(NSData *data, NSError *error)
         {
             if(data != nil) {
                 [self onProviderReadDone:provider
                                     data:data
                                    error:error
                                cacheMode:YES];
             }
         }];
    }
    else if (OfflineDetector.sharedInstance.isOffline && providerCanFallbackToOfflineCache(provider, self.safe)) {
        NSString * modDateStr = getLastCachedDate(self.safe);
        NSString* message = [NSString stringWithFormat:@"Could not reach %@, it looks like you may be offline, would you like to use a read-only offline cache version of this safe instead?\n\nLast Cached: %@", provider.displayName, modDateStr];
        
        [self openWithOfflineCacheFile:message];
    }
    else {
        [provider read:self.safe
        viewController:self.viewController
            completion:^(NSData *data, NSError *error)
         {
             [self onProviderReadDone:provider
                                 data:data
                                error:error
                            cacheMode:NO];
         }];
    }
}

BOOL providerCanFallbackToOfflineCache(id<SafeStorageProvider> provider, SafeMetaData* safe) {
    BOOL basic = provider && provider.cloudBased &&
        !(provider.storageId == kiCloud && Settings.sharedInstance.iCloudOn) &&
        safe.offlineCacheEnabled && safe.offlineCacheAvailable;
    
    if(basic) {
        NSDate *modDate = [[LocalDeviceStorageProvider sharedInstance] getOfflineCacheFileModificationDate:safe];
    
        return modDate != nil;
    }
    
    return NO;
}

- (void)onProviderReadDone:(id<SafeStorageProvider>)provider
                      data:(NSData *)data error:(NSError *)error
                 cacheMode:(BOOL)cacheMode {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (error != nil || data == nil) {
            NSLog(@"Error: %@", error);
            if(providerCanFallbackToOfflineCache(provider, self.safe)) {
                NSString * modDateStr = getLastCachedDate(self.safe);
                NSString* message = [NSString stringWithFormat:@"There was a problem reading the safe on %@. would you like to use a read-only offline cache version of this safe instead?\n\nLast Cached: %@", provider.displayName, modDateStr];
                
                [self openWithOfflineCacheFile:message];
            }
            else {
                [Alerts error:self.viewController title:@"There was a problem opening the safe." error:error completion:^{
                    self.completion(nil);
                }];
            }
        }
        else {
            [self openSafeWithData:data
                          provider:provider
                         cacheMode:cacheMode];
        }
    });
}

- (void)openSafeWithData:(NSData *)data
                provider:(id)provider
               cacheMode:(BOOL)cacheMode {
    [SVProgressHUD showWithStatus:@"Decrypting..."];
    
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(void){
        NSError *error;
        DatabaseModel *openedSafe = [[DatabaseModel alloc] initExistingWithDataAndPassword:data
                                                                                  password:self.masterPassword
                                                                             keyFileDigest:self.keyFileDigest
                                                                                     error:&error];
        
        dispatch_async(dispatch_get_main_queue(), ^(void){
            [self openSafeWithDataDone:error
                            openedSafe:openedSafe
                             cacheMode:cacheMode
                              provider:provider
                                  data:data];
        });
    });
}

- (void)openSafeWithDataDone:(NSError*)error
                  openedSafe:(DatabaseModel*)openedSafe
                   cacheMode:(BOOL)cacheMode
                    provider:(id)provider
                        data:(NSData *)data {
    [SVProgressHUD dismiss];
    
    if(openedSafe == nil) {
        [Alerts error:self.viewController title:@"There was a problem opening the safe." error:error];
        self.completion(nil);
        return;
    }
    
    if (error) {
        if (error.code == -2) {
            if(self.isTouchIdOpen) { // Password incorrect - Either in our Keychain or on initial entry. Remove safe from Touch ID enrol.
                self.safe.isEnrolledForTouchId = NO;
                [self.safe removeTouchIdPassword]; // TODO:
                [SafesList.sharedInstance update:self.safe];
                
                [Alerts info:self.viewController
                       title:@"Could not open safe"
                     message:[NSString stringWithFormat:@"The linked password was incorrect for this safe. This safe has been unlinked from %@.", self.biometricIdName]] ;
            }
            else {
                [Alerts info:self.viewController
                       title:@"Incorrect Password"
                     message:@"The password was incorrect for this safe."];
            }
        }
        else {
            [Alerts error:self.viewController title:@"There was a problem opening the safe." error:error];
        }
        
        self.completion(nil);
    }
    else {
        if (self.askAboutTouchIdEnrolIfAppropriate &&
            !cacheMode &&
            self.safe.isTouchIdEnabled &&
            !self.safe.isEnrolledForTouchId &&
            [IOsUtils isTouchIDAvailable] &&
            [[Settings sharedInstance] isProOrFreeTrial]) {
            [Alerts yesNo:self.viewController
                    title:[NSString stringWithFormat:@"Use %@ to Open Safe?", self.biometricIdName]
                  message:[NSString stringWithFormat:@"Would you like to use %@ to open this safe?", self.biometricIdName]
                   action:^(BOOL response) {
                       if (response) {
                           self.safe.isEnrolledForTouchId = YES;
                           [self.safe setTouchIdPassword:openedSafe.masterPassword];
                           [SafesList.sharedInstance update:self.safe];

#ifndef IS_APP_EXTENSION
                           [ISMessages showCardAlertWithTitle:[NSString stringWithFormat:@"%@ Enrol Successful", self.biometricIdName]
                                                      message:[NSString stringWithFormat:@"You can now use %@ with this safe. Opening...", self.biometricIdName]
                                                     duration:0.75f
                                                  hideOnSwipe:YES
                                                    hideOnTap:YES
                                                    alertType:ISAlertTypeSuccess
                                                alertPosition:ISAlertPositionTop
                                                      didHide:^(BOOL finished) {
                                                          [self onSuccessfulSafeOpen:cacheMode
                                                                            provider:provider
                                                                          openedSafe:openedSafe
                                                                                data:data];
                                                      }];
#else
                           [self onSuccessfulSafeOpen:cacheMode provider:provider openedSafe:openedSafe data:data];
#endif
                       }
                       else{
                           self.safe.isTouchIdEnabled = NO;
                           [self.safe setTouchIdPassword:openedSafe.masterPassword];
                           [SafesList.sharedInstance update:self.safe];
                           
                           [self onSuccessfulSafeOpen:cacheMode
                                             provider:provider
                                           openedSafe:openedSafe
                                                 data:data];
                       }
                   }];
        }
        else {
            [self onSuccessfulSafeOpen:cacheMode provider:provider openedSafe:openedSafe data:data];
        }
    }
}

-(void)onSuccessfulSafeOpen:(BOOL)cacheMode
                   provider:(id)provider
                 openedSafe:(DatabaseModel *)openedSafe
                       data:(NSData *)data {
    Model *viewModel = [[Model alloc] initWithSafeDatabase:openedSafe
                                                  metaData:self.safe
                                           storageProvider:cacheMode ? nil : provider // Guarantee nothing can be written!
                                                 cacheMode:cacheMode
                                                isReadOnly:NO]; // ![[Settings sharedInstance] isProOrFreeTrial]
    
    if (!cacheMode)
    {
        if(self.safe.offlineCacheEnabled) {
            [viewModel updateOfflineCacheWithData:data];
        }
        if(self.safe.autoFillCacheEnabled) {
            [viewModel updateAutoFillCacheWithData:data];
        }
    }
    
    self.completion(viewModel);
}

static NSString *getLastCachedDate(SafeMetaData *safe) {
    NSDate *modDate = [[LocalDeviceStorageProvider sharedInstance] getOfflineCacheFileModificationDate:safe];

    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.timeStyle = NSDateFormatterShortStyle;
    df.dateStyle = NSDateFormatterShortStyle;
    df.doesRelativeDateFormatting = YES;
    df.locale = NSLocale.currentLocale;
    
    NSString *modDateStr = [df stringFromDate:modDate];
    return modDateStr;
}

- (void)openWithOfflineCacheFile:(NSString *)message {
    [Alerts yesNo:self.viewController
            title:@"Use Offline Cache?"
          message:message
           action:^(BOOL response) {
               if (response) {
                   [[LocalDeviceStorageProvider sharedInstance] readOfflineCachedSafe:self.safe
                                                                       viewController:self.viewController
                                                                           completion:^(NSData *data, NSError *error)
                    {
                        if(data != nil) {
                            [self onProviderReadDone:nil
                                                data:data
                                               error:error
                                           cacheMode:YES];
                        }
                    }];
               }
               else {
                   self.completion(nil);
               }
           }];

}

- (void)promptForPasswordAndOrKeyFile {
    NSString *title = [NSString stringWithFormat:@"Password for %@", self.safe.nickName];
    
    self.alertController = [UIAlertController alertControllerWithTitle:title
                                                               message:@"Please Provide Credentials"
                                                        preferredStyle:UIAlertControllerStyleAlert];
    
    [self.alertController addTextFieldWithConfigurationHandler:^(UITextField *_Nonnull textField) {
        textField.secureTextEntry = YES;
    }];
    
    UIAlertAction *defaultAction = [UIAlertAction actionWithTitle:@"OK"
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction *a) {
                                                    self.masterPassword = self.alertController.textFields[0].text;
                                                    self.passwordAndKeyFileCompletionBlock(YES);
                                                }];
    
    UIAlertAction *keyFileAction = [UIAlertAction actionWithTitle:@"Key File..."
                                                            style:kNilOptions
                                                          handler:^(UIAlertAction *a) {
                                                              self.masterPassword = self.alertController.textFields[0].text;
                                                              [self onUseKeyFile:self.viewController];
                                                          }];
    
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"Cancel"
                                                           style:UIAlertActionStyleCancel
                                                         handler:^(UIAlertAction *a) {
                                                             self.passwordAndKeyFileCompletionBlock(NO);
                                                         }];
    
    [self.alertController addAction:defaultAction];
    [self.alertController addAction:keyFileAction];
    [self.alertController addAction:cancelAction];
    
    [self.viewController presentViewController:self.alertController animated:YES completion:nil];
}

- (void)onUseKeyFile:(UIViewController*)parentVc {
    UIDocumentPickerViewController *vc = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[(NSString*)kUTTypeItem] inMode:UIDocumentPickerModeImport];
    vc.delegate = self;
    
    [parentVc presentViewController:vc animated:YES completion:nil];
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
    self.passwordAndKeyFileCompletionBlock(NO);
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSLog(@"didPickDocumentsAtURLs: %@", urls);
    
    NSURL* url = [urls objectAtIndex:0];
    // NSString *filename = [url.absoluteString lastPathComponent];
    
    NSError* error;
    NSData* data = [NSData dataWithContentsOfURL:url options:kNilOptions error:&error];
    
    if(!data) {
        NSLog(@"Error: %@", error);
    }
    else {
        self.keyFileDigest = sha256(data);
    }
    
    self.passwordAndKeyFileCompletionBlock(YES);
}

@end
