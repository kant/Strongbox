//
//  WebDAVStorageProvider.m
//  Strongbox
//
//  Created by Mark on 11/12/2018.
//  Copyright © 2018 Mark McGuill. All rights reserved.
//

#import "WebDAVStorageProvider.h"
#import "WebDAVSessionConfiguration.h"
#import "NSArray+Extensions.h"
#import "WebDAVProviderData.h"
#import "Utils.h"
#import "WebDAVConfigurationViewController.h"
#import "SVProgressHUD.h"

@interface WebDAVStorageProvider ()

@property DAVSession* maintainedSessionForListings;
@property WebDAVSessionConfiguration* maintainedConfigurationForListings;

@end

@implementation WebDAVStorageProvider

+ (instancetype)sharedInstance {
    static WebDAVStorageProvider *sharedInstance = nil;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        sharedInstance = [[WebDAVStorageProvider alloc] init];
    });
    return sharedInstance;
}

- (instancetype)init {
    if(self = [super init]) {
        _displayName = @"WebDAV";
        _icon = @"webdav-32x32";
        _storageId = kWebDAV;
        _cloudBased = YES;
        _providesIcons = NO;
        _browsableNew = YES;
        _browsableExisting = YES;
        _rootFolderOnly = NO;
    }
    
    return self;
}

- (void)request:(DAVRequest *)aRequest didFailWithError:(NSError *)error {
    if(aRequest.strongboxCompletion) {
        aRequest.strongboxCompletion(NO, nil, error);
    }
}

- (void)request:(DAVRequest *)aRequest didSucceedWithResult:(id)result {
    if(aRequest.strongboxCompletion) {
        aRequest.strongboxCompletion(YES, result, nil);
    }
}

-(void)connect:(WebDAVSessionConfiguration*)config
viewController:(UIViewController*)viewController
    completion:(void (^)(BOOL userCancelled, DAVSession* session, WebDAVSessionConfiguration* configuration, NSError* error))completion {
    if(config == nil) {
        if(self.unitTestSessionConfiguration != nil) { // handy for unit testing
            config = self.unitTestSessionConfiguration;
        }
        else {
            WebDAVConfigurationViewController *vc = [[WebDAVConfigurationViewController alloc] init];
            __weak WebDAVConfigurationViewController* weakRef = vc;
            vc.onDone = ^(BOOL success) {
                [viewController dismissViewControllerAnimated:YES completion:^{
                    if(success) {
                        DAVCredentials *credentials = [DAVCredentials credentialsWithUsername:weakRef.configuration.username password:weakRef.configuration.password];
                        DAVSession *session = [[DAVSession alloc] initWithRootURL:weakRef.configuration.host credentials:credentials];
                        session.allowUntrustedCertificate = weakRef.configuration.allowUntrustedCertificate;
                        
                        completion(NO, session, weakRef.configuration, nil);
                    }
                    else {
                        completion(YES, nil, nil, nil);
                    }
                }];
            };

            vc.modalPresentationStyle = UIModalPresentationFormSheet;
            [viewController presentViewController:vc animated:YES completion:nil];
            return;
        }
    }
    
    DAVCredentials *credentials = [DAVCredentials credentialsWithUsername:config.username password:config.password];
    DAVSession *session = [[DAVSession alloc] initWithRootURL:config.host credentials:credentials];
    session.allowUntrustedCertificate = config.allowUntrustedCertificate;
    
    completion(NO, session, config, nil);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)create:(NSString *)nickName
     extension:(NSString *)extension
          data:(NSData *)data
  parentFolder:(NSObject *)parentFolder
viewController:(UIViewController *)viewController
    completion:(void (^)(SafeMetaData *, NSError *))completion {
    if(self.maintainSessionForListings && self.maintainedSessionForListings) { // Create New
        [self createWithSession:nickName extension:extension data:data
                   parentFolder:parentFolder session:self.maintainedSessionForListings
                  configuration:self.maintainedConfigurationForListings completion:completion];
    }
    else {
        [self connect:nil viewController:viewController completion:^(BOOL userCancelled, DAVSession *session, WebDAVSessionConfiguration *configuration, NSError *error) {
            if(userCancelled || !session || error) {
                NSError* error = [Utils createNSError:@"Could not connect to server." errorCode:-2];
                completion(nil, error);
                return;
            }
            
            [self createWithSession:nickName extension:extension data:data
                       parentFolder:parentFolder session:session
                      configuration:configuration completion:completion];
        }];
    }
}

- (void)createWithSession:(NSString *)nickName
                extension:(NSString *)extension
                     data:(NSData *)data
             parentFolder:(NSObject *)parentFolder
                  session:(DAVSession*)session
            configuration:(WebDAVSessionConfiguration*)configuration
               completion:(void (^)(SafeMetaData *, NSError *))completion {
    NSString *desiredFilename = [NSString stringWithFormat:@"%@.%@", nickName, extension];
    
    //NSString *dir = getPathFromParentFolderObject(parentFolder);
    //NSString *path = [NSString pathWithComponents:@[dir, desiredFilename]];
    
    WebDAVProviderData* providerData = (WebDAVProviderData*)parentFolder;
    NSString* root = providerData ? (providerData.href.length ? providerData.href : @"/") : @"/";
    NSString* path = [[NSURL URLWithString:root] URLByAppendingPathComponent:desiredFilename].absoluteString;
    
    DAVPutRequest *request = [[DAVPutRequest alloc] initWithPath:path];
    request.data = data;
    request.delegate = self;
    request.strongboxCompletion = ^(BOOL success, id result, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [SVProgressHUD dismiss];
        });
        
        if(!success) {
            completion(nil, error);
        }
        else {
            WebDAVProviderData* providerData = makeProviderData(path, configuration);
            SafeMetaData *metadata = [self getSafeMetaData:nickName providerData:providerData];
            completion(metadata, nil);
        }
    };
    
    dispatch_async(dispatch_get_main_queue(), ^{
        [SVProgressHUD showWithStatus:@"Creating"];
    });
    
    [session enqueueRequest:request];
}

//static NSString *getPathFromParentFolderObject(NSObject *parentFolder) {
//    WebDAVProviderData* providerData = (WebDAVProviderData*)parentFolder;
//    NSString* path = providerData ? (providerData.href.length ? providerData.href : @"/") : @"/";
//    return path;
//}

- (void)list:(NSObject *)parentFolder
viewController:(UIViewController *)viewController
  completion:(void (^)(BOOL, NSArray<StorageBrowserItem *> *, NSError *))completion {
    if(self.maintainSessionForListings && self.maintainedSessionForListings) {
        [self listWithSession:self.maintainedSessionForListings
                    parentFolder:parentFolder
                    configuration:self.maintainedConfigurationForListings
                       completion:completion];
    }
    else {
        [self connect:nil viewController:viewController completion:^(BOOL userCancelled, DAVSession *session, WebDAVSessionConfiguration *configuration, NSError *error) {
            if(userCancelled) {
                completion(YES, nil, nil);
                return;
            }
        
            if(!session || error) {
                NSError* error = [Utils createNSError:@"Could not connect to server." errorCode:-2];
                completion(NO, nil, error);
                return;
            }
        
            if(self.maintainSessionForListings) {
                self.maintainedSessionForListings = session;
                self.maintainedConfigurationForListings = configuration;
            }
            
            [self listWithSession:session parentFolder:parentFolder configuration:configuration completion:completion];
        }];
    }
}

- (void)listWithSession:(DAVSession*)session
           parentFolder:(NSObject*)parentFolder
          configuration:(WebDAVSessionConfiguration*)configuration
             completion:(void (^)(BOOL, NSArray<StorageBrowserItem *> *, NSError *))completion {
    WebDAVProviderData* providerData = (WebDAVProviderData*)parentFolder;
    NSString* path = providerData ? (providerData.href.length ? providerData.href : @"/") : @"/";
    DAVListingRequest* listingRequest = [[DAVListingRequest alloc] initWithPath:path];

    listingRequest.delegate = self;
    listingRequest.strongboxCompletion = ^(BOOL success, id result, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [SVProgressHUD dismiss];
        });
        if(error) {
            completion(NO, nil, error);
            return;
        }
        else {
            NSArray<DAVResponseItem*>* files = result;
            

            NSURL *parentUrl = [NSURL URLWithString:path];
            if([parentUrl scheme] == nil) {
                parentUrl = [configuration.host URLByAppendingPathComponent:path];
            }

            files = [files filter:^BOOL(DAVResponseItem * _Nonnull obj) {
                return obj.href && ![parentUrl.absoluteString isEqualToString:obj.href.absoluteString];
            }];
            
            NSArray<StorageBrowserItem*>* browserItems = [files map:^id _Nonnull(DAVResponseItem * _Nonnull obj, NSUInteger idx) {
                StorageBrowserItem* sbi = [[StorageBrowserItem alloc] init];
                sbi.name = [[obj.href lastPathComponent] stringByRemovingPercentEncoding];
                sbi.folder = obj.resourceType == DAVResourceTypeCollection;
                sbi.providerData = makeProviderData(obj.href.absoluteString, configuration);
            
                return sbi;
            }];
            
            
            completion(NO, browserItems, nil);
        }
    };

    dispatch_async(dispatch_get_main_queue(), ^{
        [SVProgressHUD showWithStatus:@"Listing..."];
    });

    [session enqueueRequest:listingRequest];
}
        

- (void)read:(SafeMetaData *)safeMetaData viewController:(UIViewController *)viewController completion:(void (^)(NSData *, NSError *))completion {
    WebDAVProviderData* providerData = [self getProviderDataFromMetaData:safeMetaData];
    [self readWithProviderData:providerData viewController:viewController completion:completion];
}

- (void)readWithProviderData:(NSObject *)providerData viewController:(UIViewController *)viewController completion:(void (^)(NSData *, NSError *))completionHandler {
    WebDAVProviderData* pd = (WebDAVProviderData*)providerData;
    [self connect:pd.sessionConfiguration viewController:viewController completion:^(BOOL userCancelled, DAVSession *session, WebDAVSessionConfiguration *configuration, NSError *error) {
        if(!session) {
            NSError* error = [Utils createNSError:@"Could not connect to server." errorCode:-2];
            completionHandler(nil, error);
            return;
        }
        
        DAVGetRequest *request = [[DAVGetRequest alloc] initWithPath:pd.href];
        request.delegate = self;
        request.strongboxCompletion = ^(BOOL success, id result, NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [SVProgressHUD dismiss];
            });
            
            if(!success) {
                completionHandler(nil, error);
            }
            else {
                completionHandler(result, error);
            }
        };
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [SVProgressHUD showWithStatus:@"Reading..."];
        });
        
        [session enqueueRequest:request];
    }];
}

- (void)update:(SafeMetaData *)safeMetaData data:(NSData *)data completion:(void (^)(NSError *))completion {
    WebDAVProviderData* providerData = [self getProviderDataFromMetaData:safeMetaData];
    
    [self connect:providerData.sessionConfiguration viewController:nil completion:^(BOOL userCancelled, DAVSession *session, WebDAVSessionConfiguration *configuration, NSError *error) {
        if(!session) {
            NSError* error = [Utils createNSError:@"Could not connect to server." errorCode:-2];
            completion(error);
            return;
        }
        
        DAVPutRequest *request = [[DAVPutRequest alloc] initWithPath:providerData.href];
        request.data = data;
        request.delegate = self;
        request.strongboxCompletion = ^(BOOL success, id result, NSError *error) {
            completion(error);
        };
        
        [session enqueueRequest:request];
    }];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static WebDAVProviderData* makeProviderData(NSString *href, WebDAVSessionConfiguration* sessionConfiguration) {
    WebDAVProviderData* ret = [[WebDAVProviderData alloc] init];
    
    ret.href = href;
    ret.sessionConfiguration = sessionConfiguration;
    
    return ret;
}

- (WebDAVProviderData*)getProviderDataFromMetaData:(SafeMetaData*)metaData {
    NSString* json = metaData.fileIdentifier;
    
    NSError* error;
    NSDictionary* dictionary = [NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding:NSUTF8StringEncoding]
                                                               options:kNilOptions
                                                                 error:&error];
    
    WebDAVProviderData* foo = [WebDAVProviderData fromSerializationDictionary:dictionary];
    
    return foo;
}

- (SafeMetaData *)getSafeMetaData:(NSString *)nickName providerData:(NSObject *)providerData {
    WebDAVProviderData* foo = (WebDAVProviderData*)providerData;
    
    NSError* error;
    NSData* data = [NSJSONSerialization dataWithJSONObject:[foo serializationDictionary] options:0 error:&error];
    
    if(error) {
        NSLog(@"%@", error);
        return nil;
    }
    
    NSString *json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
    return [[SafeMetaData alloc] initWithNickName:nickName
                                  storageProvider:self.storageId
                                         fileName:[[foo.href lastPathComponent] stringByRemovingPercentEncoding]
                                   fileIdentifier:json];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)delete:(SafeMetaData *)safeMetaData completion:(void (^)(NSError *))completion {
    // NOTIMPL
}

- (void)loadIcon:(NSObject *)providerData viewController:(UIViewController *)viewController completion:(void (^)(UIImage *))completionHandler {
    // NOTIMPL
}
    
@end
