#ifndef _DatabaseModel_h
#define _DatabaseModel_h

#import <Foundation/Foundation.h>
#import "Node.h"
#import "AbstractDatabaseMetadata.h"
#import "AbstractDatabaseFormatAdaptor.h"
#import "DatabaseAttachment.h"
#import "UiAttachment.h"

NS_ASSUME_NONNULL_BEGIN

extern NSInteger const kSearchScopeTitle;
extern NSInteger const kSearchScopeUsername;
extern NSInteger const kSearchScopePassword;
extern NSInteger const kSearchScopeUrl;
extern NSInteger const kSearchScopeAll;

@interface DatabaseModel : NSObject

+ (BOOL)isAValidSafe:(nullable NSData *)candidate error:(NSError**)error;
+ (NSString*_Nonnull)getLikelyFileExtension:(NSData *_Nonnull)candidate;
+ (BOOL)isAutoFillLikelyToCrash:(NSData*)data;
+ (DatabaseFormat)getLikelyDatabaseFormat:(NSData *)candidate;

+ (nullable id<AbstractDatabaseFormatAdaptor>)getAdaptor:(DatabaseFormat)format;

- (instancetype _Nullable )init NS_UNAVAILABLE;

- (instancetype)initNewWithPassword:(nullable NSString *)password keyFileDigest:(nullable NSData*)keyFileDigest format:(DatabaseFormat)format;

- (instancetype _Nullable )initExistingWithDataAndPassword:(NSData *_Nonnull)data
                                                  password:(NSString *_Nonnull)password
                                                     error:(NSError *_Nonnull*_Nonnull)ppError;

- (instancetype _Nullable )initExistingWithDataAndPassword:(NSData *_Nonnull)data
                                                  password:(NSString *__nullable)password
                                             keyFileDigest:(NSData* __nullable)keyFileDigest
                                                     error:(NSError *_Nonnull*_Nonnull)ppError;

- (NSData* _Nullable)getAsData:(NSError*_Nonnull*_Nonnull)error;

- (BOOL)isDereferenceableText:(NSString*)text;
- (NSString*)dereference:(NSString*)text node:(Node*)node;

- (void)addNodeAttachment:(Node *)node attachment:(UiAttachment*)attachment;
- (void)removeNodeAttachment:(Node *)node atIndex:(NSUInteger)atIndex;
- (void)setNodeAttachments:(Node*)node attachments:(NSArray<UiAttachment*>*)attachments;
- (void)setNodeCustomIcon:(Node*)node data:(NSData*)data;

- (NSArray<Node*>*)search:(NSString *)searchText
                    scope:(NSInteger)scope
              dereference:(BOOL)dereference
    includeKeePass1Backup:(BOOL)includeKeePass1Backup
        includeRecycleBin:(BOOL)includeRecycleBin;

- (BOOL)isTitleMatches:(NSString*)searchText node:(Node*)node dereference:(BOOL)dereference;
- (BOOL)isUsernameMatches:(NSString*)searchText node:(Node*)node dereference:(BOOL)dereference;
- (BOOL)isPasswordMatches:(NSString*)searchText node:(Node*)node dereference:(BOOL)dereference;
- (BOOL)isUrlMatches:(NSString*)searchText node:(Node*)node dereference:(BOOL)dereference;
- (BOOL)isAllFieldsMatches:(NSString*)searchText node:(Node*)node dereference:(BOOL)dereference;
- (NSArray<NSString*>*)getSearchTerms:(NSString *)searchText;

- (NSString *)getGroupPathDisplayString:(Node *)vm;
- (NSString *)getSearchParentGroupPathDisplayString:(Node *)vm;

- (NSArray<Node*>*)sortItemsForBrowse:(NSArray<Node*>*)items;
- (NSString*)getBrowseItemSubtitle:(Node*)node;

@property (nonatomic, readonly, nonnull) Node* rootGroup;
@property (nonatomic, readonly, nonnull) id<AbstractDatabaseMetadata> metadata;
@property (nonatomic, readonly, nonnull) NSArray<DatabaseAttachment*> *attachments;
@property (nonatomic, readonly, nonnull) NSDictionary<NSUUID*, NSData*>* customIcons;

@property (nonatomic, readonly, nonnull) NSArray<Node*> *allNodes;
@property (nonatomic, readonly, nonnull) NSArray<Node*> *allRecords;
@property (nonatomic, readonly, nonnull) NSArray<Node*> *allGroups;
@property (nonatomic, readonly, nonnull) NSArray<Node*> *activeRecords;
@property (nonatomic, readonly, nonnull) NSArray<Node*> *activeGroups;

@property (nonatomic, retain, nullable) NSString *masterPassword;
@property (nonatomic, retain, nullable) NSData *keyFileDigest;
@property (nonatomic, readonly) DatabaseFormat format;
@property (nonatomic, readonly, nonnull) NSString* fileExtension;

// Helpers

@property (nonatomic, readonly, copy) NSSet<NSString*>* _Nonnull usernameSet;
@property (nonatomic, readonly, copy) NSSet<NSString*>* _Nonnull emailSet;
@property (nonatomic, readonly, copy) NSSet<NSString*>* _Nonnull urlSet;
@property (nonatomic, readonly, copy) NSSet<NSString*>* _Nonnull passwordSet;

@property (nonatomic, readonly) NSString* _Nonnull mostPopularUsername;
@property (nonatomic, readonly) NSString* _Nonnull mostPopularEmail;
@property (nonatomic, readonly) NSString* _Nonnull mostPopularPassword; 
@property (nonatomic, readonly) NSInteger numberOfRecords;
@property (nonatomic, readonly) NSInteger numberOfGroups;

@property (readonly) BOOL recycleBinEnabled; // Read-Only until we allow config
@property (readonly) Node* recycleBinNode;
- (void)createNewRecycleBinNode;

@property (nullable, readonly) Node* keePass1BackupNode;


@end

#endif // ifndef _DatabaseModel_h

NS_ASSUME_NONNULL_END
