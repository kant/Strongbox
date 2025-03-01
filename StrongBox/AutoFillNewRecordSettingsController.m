//
//  AutoFillNewRecordSettingsController.m
//  Strongbox-iOS
//
//  Created by Mark on 04/10/2018.
//  Copyright © 2018 Mark McGuill. All rights reserved.
//

#import "AutoFillNewRecordSettingsController.h"
#import "Settings.h"
#import "Alerts.h"

@interface AutoFillNewRecordSettingsController ()

@end

@implementation AutoFillNewRecordSettingsController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    [self bindToSettings];

    if (@available(iOS 11.0, *)) {
        self.navigationController.navigationBar.prefersLargeTitles = NO;
    }
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    AutoFillNewRecordSettings *settings = Settings.sharedInstance.autoFillNewRecordSettings;
    Alerts *alerts = [[Alerts alloc] initWithTitle:@"Custom Auto Fill"
                                           message:@"Please enter a new custom auto fill for this field"];
    
    if(indexPath.section == 0 && indexPath.row == 1)
    {
        [alerts OkCancelWithTextFieldNotEmpty:self
                                textFieldText:settings.titleCustomAutoFill
                                   completion:^(NSString *text, BOOL response) {
            if(response) {
                settings.titleCustomAutoFill = text;
                Settings.sharedInstance.autoFillNewRecordSettings = settings;
                
                dispatch_async(dispatch_get_main_queue(), ^(void) {
                    [self bindToSettings];
                    [self.tableView reloadRowsAtIndexPaths:@[[NSIndexPath indexPathForRow:1 inSection:0]]
                                          withRowAnimation:UITableViewRowAnimationFade];
                });
            }
        }];
    }
    else if(indexPath.section == 1 && indexPath.row == 1)
    {
        [alerts OkCancelWithTextFieldNotEmpty:self
                                textFieldText:settings.usernameCustomAutoFill
                                   completion:^(NSString *text, BOOL response) {
                                       if(response) {
                                           settings.usernameCustomAutoFill = text;
                                           Settings.sharedInstance.autoFillNewRecordSettings = settings;
                                           
                                           dispatch_async(dispatch_get_main_queue(), ^(void) {
                                               [self bindToSettings];
                                               [self.tableView reloadRowsAtIndexPaths:@[[NSIndexPath indexPathForRow:1 inSection:1]]
                                                                     withRowAnimation:UITableViewRowAnimationFade];
                                           });
                                       }
                                   }];
    }
    else if(indexPath.section == 2 && indexPath.row == 1)
    {
        [alerts OkCancelWithTextFieldNotEmpty:self
                                textFieldText:settings.passwordCustomAutoFill
                                   completion:^(NSString *text, BOOL response) {
                                       if(response) {
                                           settings.passwordCustomAutoFill = text;
                                           Settings.sharedInstance.autoFillNewRecordSettings = settings;
                                           
                                           dispatch_async(dispatch_get_main_queue(), ^(void) {
                                               [self bindToSettings];
                                               [self.tableView reloadRowsAtIndexPaths:@[[NSIndexPath indexPathForRow:1 inSection:2]]
                                                                     withRowAnimation:UITableViewRowAnimationFade];
                                           });
                                       }
                                   }];
    }
    else if(indexPath.section == 3 && indexPath.row == 1)
    {
        [alerts OkCancelWithTextFieldNotEmpty:self
                                textFieldText:settings.emailCustomAutoFill
                                   completion:^(NSString *text, BOOL response) {
                                       if(response) {
                                           settings.emailCustomAutoFill = text;
                                           Settings.sharedInstance.autoFillNewRecordSettings = settings;
                                           
                                           dispatch_async(dispatch_get_main_queue(), ^(void) {
                                               [self bindToSettings];
                                               [self.tableView reloadRowsAtIndexPaths:@[[NSIndexPath indexPathForRow:1 inSection:3]]
                                                                     withRowAnimation:UITableViewRowAnimationFade];
                                           });
                                       }
                                   }];
    }
    else if(indexPath.section == 4 && indexPath.row == 1)
    {
        [alerts OkCancelWithTextFieldNotEmpty:self
                                textFieldText:settings.urlCustomAutoFill
                                   completion:^(NSString *text, BOOL response) {
                                       if(response) {
                                           settings.urlCustomAutoFill = text;
                                           Settings.sharedInstance.autoFillNewRecordSettings = settings;
                                           
                                           dispatch_async(dispatch_get_main_queue(), ^(void) {
                                               [self bindToSettings];
                                               [self.tableView reloadRowsAtIndexPaths:@[[NSIndexPath indexPathForRow:1 inSection:4]]
                                                                     withRowAnimation:UITableViewRowAnimationFade];
                                           });
                                       }
                                   }];
    }
    else if(indexPath.section == 5 && indexPath.row == 1)
    {
        [alerts OkCancelWithTextFieldNotEmpty:self
                                textFieldText:settings.notesCustomAutoFill
                                   completion:^(NSString *text, BOOL response) {
                                       if(response) {
                                           settings.notesCustomAutoFill = text;
                                           Settings.sharedInstance.autoFillNewRecordSettings = settings;
                                           
                                           dispatch_async(dispatch_get_main_queue(), ^(void) {
                                               [self bindToSettings];
                                               [self.tableView reloadRowsAtIndexPaths:@[[NSIndexPath indexPathForRow:1 inSection:5]]
                                                                     withRowAnimation:UITableViewRowAnimationFade];
                                           });
                                       }
                                   }];
    }
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath
{
    AutoFillNewRecordSettings *settings = Settings.sharedInstance.autoFillNewRecordSettings;

    if(indexPath.section == 0 && indexPath.row == 1)
    {
        if(settings.titleAutoFillMode != kCustom) {
            return 0; //set the hidden cell's height to 0
        }
    }
    else if(indexPath.section == 1 && indexPath.row == 1)
    {
        if(settings.usernameAutoFillMode != kCustom) {
            return 0; //set the hidden cell's height to 0
        }
    }
    else if(indexPath.section == 2 && indexPath.row == 1)
    {
        if(settings.passwordAutoFillMode != kCustom) {
            return 0; //set the hidden cell's height to 0
        }
    }
    else if(indexPath.section == 3 && indexPath.row == 1)
    {
        if(settings.emailAutoFillMode != kCustom) {
            return 0; //set the hidden cell's height to 0
        }
    }
    else if(indexPath.section == 4 && indexPath.row == 1)
    {
        if(settings.urlAutoFillMode != kCustom) {
            return 0; //set the hidden cell's height to 0
        }
    }
    else if(indexPath.section == 5 && indexPath.row == 1)
    {
        if(settings.notesAutoFillMode != kCustom) {
            return 0; //set the hidden cell's height to 0
        }
    }
    
    return [super tableView:tableView heightForRowAtIndexPath:indexPath];
}

- (void)bindToSettings {
    AutoFillNewRecordSettings *settings = Settings.sharedInstance.autoFillNewRecordSettings;
    
    // Title Options: Default / Custom
    
    int index = [self autoFillModeToSegmentIndex:settings.titleAutoFillMode];
    self.segmentTitle.selectedSegmentIndex = index != -1 ? index : 1;
    
    self.labelTitle.text = settings.titleAutoFillMode == kCustom ? settings.titleCustomAutoFill : @"";

    // Username Options: None / Most Used / Custom
    
    // KLUDGE: This is a bit hacky but saves some RSI typing... :/
    index = [self autoFillModeToSegmentIndex:settings.usernameAutoFillMode];
    self.segmentUsername.selectedSegmentIndex = index != -1 ? index : 2;
    
    self.labelUsername.text = settings.usernameAutoFillMode == kCustom ? settings.usernameCustomAutoFill : @"";

    // Password Options: None / Most Used / Generated / Custom
    
    index = [self autoFillModeToSegmentIndex:settings.passwordAutoFillMode];
    self.segmentPassword.selectedSegmentIndex = index != -1 ? index : 2;
    
    self.labelPassword.text = settings.passwordAutoFillMode == kCustom ? settings.passwordCustomAutoFill : @"";

    // Email Options: None / Most Used / Custom
    
    index = [self autoFillModeToSegmentIndex:settings.emailAutoFillMode];
    self.segmentEmail.selectedSegmentIndex = index != -1 ? index : 2;
    
    self.labelEmail.text = settings.emailAutoFillMode == kCustom ? settings.emailCustomAutoFill : @"";

    // URL Options: None / Custom
    
    index = [self autoFillModeToSegmentIndex:settings.urlAutoFillMode];
    self.segmentUrl.selectedSegmentIndex = index != -1 ? index : 1;
    
    self.labelUrl.text = settings.urlAutoFillMode == kCustom ? settings.urlCustomAutoFill : @"";

    // Notes Options: None / Custom
    
    index = [self autoFillModeToSegmentIndex:settings.notesAutoFillMode];
    self.segmentNotes.selectedSegmentIndex = index != -1 ? index : 1;
    
    self.labelNotes.text = settings.notesAutoFillMode == kCustom ? settings.notesCustomAutoFill : @"";
    
    [self.tableView reloadData];
}

- (int)autoFillModeToSegmentIndex:(AutoFillMode)mode {
    // KLUDGE: This is a bit hacky but saves some RSI typing... :/
    
    switch (mode) {
        case kNone:
        case kDefault:
            return 0;
            break;
        case kMostUsed:
        case kGenerated:
            return 1;
            break;
        case kCustom:
            return -1;
            break;
        default:
            NSLog(@"Ruh ROh... ");
            break;
    }
}

- (IBAction)onTitleSegmentChanged:(id)sender {
    AutoFillNewRecordSettings *settings = Settings.sharedInstance.autoFillNewRecordSettings;
    
    settings.titleAutoFillMode = self.segmentTitle.selectedSegmentIndex == 0 ? kDefault : kCustom;
    
    Settings.sharedInstance.autoFillNewRecordSettings = settings;
    
    [self bindToSettings];

    [self.tableView reloadRowsAtIndexPaths:@[[NSIndexPath indexPathForRow:1 inSection:0]]
                          withRowAnimation:UITableViewRowAnimationFade];
}

- (IBAction)onUsernameSegmentChanged:(id)sender {
    AutoFillNewRecordSettings *settings = Settings.sharedInstance.autoFillNewRecordSettings;
    
    switch (self.segmentUsername.selectedSegmentIndex) {
        case 0:
            settings.usernameAutoFillMode = kNone;
            break;
        case 1:
            settings.usernameAutoFillMode = kMostUsed;
            break;
        case 2:
            settings.usernameAutoFillMode = kCustom;
            break;
        default:
            NSLog(@"Default Switch statement hit unexpected. Username.");
            break;
    }
    
    Settings.sharedInstance.autoFillNewRecordSettings = settings;
    [self bindToSettings];
    
    [self.tableView reloadRowsAtIndexPaths:@[[NSIndexPath indexPathForRow:1 inSection:1]]
                          withRowAnimation:UITableViewRowAnimationFade];
}

- (IBAction)onPasswordSegmentChanged:(id)sender {
    AutoFillNewRecordSettings *settings = Settings.sharedInstance.autoFillNewRecordSettings;
    
    switch (self.segmentPassword.selectedSegmentIndex) {
        case 0: // None
            settings.passwordAutoFillMode = kNone;
            break;
        case 1: // Generated
            settings.passwordAutoFillMode = kGenerated;
            break;
        case 2: // Custom
            settings.passwordAutoFillMode = kCustom;
            break;
        default:
            NSLog(@"Default Switch statement hit unexpected. Password.");
            break;
    }
    
    Settings.sharedInstance.autoFillNewRecordSettings = settings;
    [self bindToSettings];

    [self.tableView reloadRowsAtIndexPaths:@[[NSIndexPath indexPathForRow:1 inSection:2]]
                          withRowAnimation:UITableViewRowAnimationFade];
}

- (IBAction)onEmailSegmentChanged:(id)sender {
    AutoFillNewRecordSettings *settings = Settings.sharedInstance.autoFillNewRecordSettings;
    
    switch (self.segmentEmail.selectedSegmentIndex) {
        case 0:
            settings.emailAutoFillMode = kNone;
            break;
        case 1:
            settings.emailAutoFillMode = kMostUsed;
            break;
        case 2:
            settings.emailAutoFillMode = kCustom;
            break;
        default:
            NSLog(@"Default Switch statement hit unexpected. Email.");
            break;
    }
    
    Settings.sharedInstance.autoFillNewRecordSettings = settings;
    [self bindToSettings];
    
    [self.tableView reloadRowsAtIndexPaths:@[[NSIndexPath indexPathForRow:1 inSection:3]]
                          withRowAnimation:UITableViewRowAnimationFade];
}

- (IBAction)onUrlSegmentChanged:(id)sender {
    AutoFillNewRecordSettings *settings = Settings.sharedInstance.autoFillNewRecordSettings;
    
    switch (self.segmentUrl.selectedSegmentIndex) {
        case 0: // None
            settings.urlAutoFillMode = kNone;
            break;
        case 1: // Custom
            settings.urlAutoFillMode = kCustom;
            break;
        default:
            NSLog(@"Default Switch statement hit unexpected. URL.");
            break;
    }
    
    Settings.sharedInstance.autoFillNewRecordSettings = settings;
    [self bindToSettings];
    
    [self.tableView reloadRowsAtIndexPaths:@[[NSIndexPath indexPathForRow:1 inSection:4]]
                          withRowAnimation:UITableViewRowAnimationFade];
}

- (IBAction)onNotesSegmentChanged:(id)sender {
    AutoFillNewRecordSettings *settings = Settings.sharedInstance.autoFillNewRecordSettings;
    
    switch (self.segmentNotes.selectedSegmentIndex) {
        case 0: // None
            settings.notesAutoFillMode = kNone;
            break;
        case 1: // Custom
            settings.notesAutoFillMode = kCustom;
            break;
        default:
            NSLog(@"Default Switch statement hit unexpected. URL.");
            break;
    }
    
    Settings.sharedInstance.autoFillNewRecordSettings = settings;
    [self bindToSettings];

    [self.tableView reloadRowsAtIndexPaths:@[[NSIndexPath indexPathForRow:1 inSection:5]]
                          withRowAnimation:UITableViewRowAnimationFade];
}

- (IBAction)onDone:(id)sender {
    self.onDone();
}

@end
