//
//  KeePassXmlModelAdaptor.m
//  Strongbox-iOS
//
//  Created by Mark on 16/10/2018.
//  Copyright © 2018 Mark McGuill. All rights reserved.
//

#import "XmlStrongboxNodeModelAdaptor.h"
#import "KeePassXmlParserDelegate.h"
#import "Utils.h"
#import "KeePassConstants.h"
#import "DatabaseAttachment.h"

@interface XmlStrongboxNodeModelAdaptor ()

@property XmlProcessingContext* xmlParsingContext;

@end

@implementation XmlStrongboxNodeModelAdaptor

- (KeePassGroup*)fromModel:(Node*)rootNode context:(XmlProcessingContext*)context error:(NSError**)error {
    self.xmlParsingContext = context;
    
    // Strongbox uses the Root Node as a dummy but KeePass the actual root node is serialized and entries are not allowed
    // to be added to it.
    
    if(rootNode.children.count != 1 || ![rootNode.children objectAtIndex:0].isGroup) {
       if(error) {
            *error = [Utils createNSError:@"Unexpected root group. More/Less than 1 child at root or non group at root" errorCode:-1];
        }
        
        NSLog(@"Unexpected root group. More/Less than 1 child at root or non group at root");
        return nil;
    }

    Node* keePassRootGroup = [rootNode.children objectAtIndex:0];    
    return [self buildXmlGroup:keePassRootGroup];
}

- (Node*)toModel:(KeePassGroup*)existingXmlRoot error:(NSError**)error {
    Node* rootNode = [[Node alloc] initAsRoot:nil];
    rootNode.linkedData = existingXmlRoot;
    
    if(existingXmlRoot) {
        if(![self buildGroup:existingXmlRoot parentNode:rootNode]) {
            if(error) {
                *error = [Utils createNSError:@"Problem building Strongbox Node model from KeePass Xml" errorCode:-1];
            }
            NSLog(@"ERROR: building groups.");
            return nil;
        }
    }
    else {
        // No Proper Root Group found in Xml Model. We'll create one
        
        Node* keePassRootGroup = [[Node alloc] initAsGroup:kDefaultRootGroupName parent:rootNode allowDuplicateGroupTitles:YES uuid:nil];
        [rootNode addChild:keePassRootGroup allowDuplicateGroupTitles:YES];
    }
    
    return rootNode;
}

- (KeePassGroup*)buildXmlGroup:(Node*)group {
    KeePassGroup *ret = [[KeePassGroup alloc] initWithContext:self.xmlParsingContext];
    KeePassGroup *previousXmlGroup = (KeePassGroup*)group.linkedData;
    
    if(group.iconId != nil) {
        ret.icon = group.iconId;
    }
    if(group.customIconUuid){
        ret.customIcon = group.customIconUuid;
    }
    
    if(previousXmlGroup) { // Retain unknown attributes/text & child elements
        ret.nonCustomisedXmlTree = previousXmlGroup.nonCustomisedXmlTree;
    }
    
    for(Node* childGroup in group.childGroups) {
        [ret.groups addObject:[self buildXmlGroup:childGroup]];
    }
    
    for(Node* childEntry in group.childRecords) {
        [ret.entries addObject:[self buildXmlEntry:childEntry stripHistory:NO]];
    }
    
    ret.name.text = group.title;
    ret.uuid.uuid = group.uuid;
    
    return ret;
}

- (Entry*)buildXmlEntry:(Node*)entry stripHistory:(BOOL)stripHistory {
    Entry *ret = [[Entry alloc] initWithContext:self.xmlParsingContext];
    Entry *previousXmlEntry = (Entry*)entry.linkedData;
    
    if(previousXmlEntry) { // Retain unknown attributes/text & child elements
        ret.nonCustomisedXmlTree = previousXmlEntry.nonCustomisedXmlTree;
    }

    ret.uuid.uuid = entry.uuid;
    
    if(entry.iconId != nil) {
        ret.icon = entry.iconId;
    }
    if(entry.customIconUuid){
        ret.customIcon = entry.customIconUuid;
    }
    
    // Times is only partially managed so need to add any customisation from original here.
    
    if(previousXmlEntry.times) {
        ret.times.nonCustomisedXmlTree = previousXmlEntry.times.nonCustomisedXmlTree;
    }
    
    ret.times.lastAccessTime.date = entry.fields.accessed;
    ret.times.lastModificationTime.date = entry.fields.modified;
    ret.times.creationTime.date = entry.fields.created;

    // Strings
    
    for (NSString* key in entry.fields.customFields.allKeys) {
        StringValue* value = entry.fields.customFields[key];
        [ret setString:key value:value.value protected:value.protected];
    }

    ret.title = entry.title;
    ret.username = entry.fields.username;
    ret.password = entry.fields.password;
    ret.url = entry.fields.url;
    ret.notes = entry.fields.notes;
    
    // Verify it's ok to strip empty strings. Looks like it is: https://sourceforge.net/p/keepass/discussion/329221/thread/fd78ba87/
    // MMcG: Don't strip emptys, it seems to be useful to allow empty values in the custom fields, or at least the
    // Windows app allows this

    // Binaries
    
    for (NodeFileAttachment *attachment in entry.fields.attachments) {
        Binary *old = (Binary*)attachment.linkedObject;
        
        Binary *xmlBinary = [[Binary alloc] initWithContext:self.xmlParsingContext];
        
        if(old) { // Copy old attributes/text etc
            [xmlBinary setXmlInfo:old.nonCustomisedXmlTree.node.xmlElementName attributes:old.nonCustomisedXmlTree.node.xmlAttributes text:old.nonCustomisedXmlTree.node.xmlText];
            [xmlBinary.key setXmlInfo:old.key.nonCustomisedXmlTree.node.xmlElementName attributes:old.key.nonCustomisedXmlTree.node.xmlAttributes text:old.key.nonCustomisedXmlTree.node.xmlText];
            [xmlBinary.value setXmlInfo:old.value.nonCustomisedXmlTree.node.xmlElementName attributes:old.value.nonCustomisedXmlTree.node.xmlAttributes text:old.value.nonCustomisedXmlTree.node.xmlText];
        }
        
        xmlBinary.key.text = attachment.filename;
        [xmlBinary.value setXmlAttribute:kBinaryValueAttributeRef value:[NSString stringWithFormat:@"%d", attachment.index]];
        
        [ret.binaries addObject:xmlBinary];
    }
    
    // History
    
    if(!stripHistory) {
        for(Node* historicalNode in entry.fields.keePassHistory) {
            Entry* historicalEntry = [self buildXmlEntry:historicalNode stripHistory:YES]; // Just in case we have accidentally left history on a historical entry itself...
            [ret.history.entries addObject:historicalEntry];
        }
    }
    
    return ret;
}

- (BOOL)buildGroup:(KeePassGroup*)group parentNode:(Node*)parentNode {
    Node* groupNode = [[Node alloc] initAsGroup:group.name.text parent:parentNode allowDuplicateGroupTitles:YES uuid:group.uuid.uuid];
    groupNode.linkedData = group; // Original KeePass Document Group...
    
    if(group.customIcon) groupNode.customIconUuid = group.customIcon;
    if(group.icon != nil) groupNode.iconId = group.icon;

    
    for (KeePassGroup *childGroup in group.groups) {
        if(![self buildGroup:childGroup parentNode:groupNode]) {
            NSLog(@"Error Builing Child Group: [%@]", childGroup);
            return NO;
        }
    }

    for (Entry *childEntry in group.entries) {
        Node * entryNode = [self nodeFromEntry:childEntry groupNode:groupNode]; // Original KeePass Document Group...
        
        if( entryNode == nil ) {
            NSLog(@"Error building node from Entry: [%@]", childEntry);
            return NO;
        }
        
        [groupNode addChild:entryNode allowDuplicateGroupTitles:YES];
    }
    
    [parentNode addChild:groupNode allowDuplicateGroupTitles:YES];

    return YES;
}

- (Node*)nodeFromEntry:(Entry *)childEntry groupNode:(Node*)groupNode {
    NodeFields *fields = [[NodeFields alloc] initWithUsername:childEntry.username
                                                          url:childEntry.url
                                                     password:childEntry.password
                                                        notes:childEntry.notes
                                                        email:@""]; // Not an official Keepass Field!
    
    fields.created = childEntry.times.creationTime.date;
    fields.accessed = childEntry.times.lastAccessTime.date;
    fields.modified = childEntry.times.lastModificationTime.date;
    
    for (Binary* binary in childEntry.binaries) {
        NSString* binaryRef = [binary.value.nonCustomisedXmlTree.node.xmlAttributes objectForKey:kBinaryValueAttributeRef];
        
        if(binaryRef) {
            int binaryIndex = [binaryRef intValue];
            
            NodeFileAttachment* attachment = [[NodeFileAttachment alloc] init];
            
            attachment.filename = binary.key.text;
            attachment.index = binaryIndex;
            attachment.linkedObject = binary;
            
//            NSLog(@"Found attachment for: %@", childEntry.title);
            
            [fields.attachments addObject:attachment];
        }
    }
    
    // Custom Fields
    
    for (NSString* key in childEntry.customStrings.allKeys) {
        StringValue* value = childEntry.customStrings[key];
        [fields.customFields setObject:value forKey:key];
    }
    
    Node* entryNode = [[Node alloc] initAsRecord:childEntry.title
                                          parent:groupNode
                                          fields:fields
                                            uuid:childEntry.uuid.uuid]; 
    
    entryNode.linkedData = childEntry;
    
    if(childEntry.customIcon) entryNode.customIconUuid = childEntry.customIcon;
    if(childEntry.icon != nil) entryNode.iconId = childEntry.icon;
    
    if(childEntry.history && childEntry.history.entries) {
        for (Entry* historicalEntry in childEntry.history.entries) {
            Node* historicalEntryNode = [self nodeFromEntry:historicalEntry groupNode:groupNode];
            [fields.keePassHistory addObject:historicalEntryNode];
        }
    }
    
    return entryNode;
}

@end
