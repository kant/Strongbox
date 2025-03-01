//
//  WelcomeMasterPasswordViewController.m
//  Strongbox-iOS
//
//  Created by Mark on 05/06/2019.
//  Copyright © 2019 Mark McGuill. All rights reserved.
//

#import "WelcomeMasterPasswordViewController.h"
#import "PasswordGenerator.h"
#import "WelcomeCreateDoneViewController.h"
#import "AddNewSafeHelper.h"
#import "Alerts.h"

@interface WelcomeMasterPasswordViewController () <UITextFieldDelegate>

@property (weak, nonatomic) IBOutlet UIButton *buttonCreate;
@property (weak, nonatomic) IBOutlet UITextField *textFieldPw;
@property SafeMetaData* database;
@property NSString* password;

@end

@implementation WelcomeMasterPasswordViewController

- (BOOL)shouldAutorotate {
    if ( UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad )
    {
        return YES; /* Device is iPad */
    }
    else {
        return NO;
    }
}

- (UIInterfaceOrientationMask)supportedInterfaceOrientations {
    if ( UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad )
    {
        return UIInterfaceOrientationMaskAll; /* Device is iPad */
    }
    else {
        return UIInterfaceOrientationMaskPortrait;
    }
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    
    self.navigationController.navigationBar.hidden = YES;
    [self.navigationController setNavigationBarHidden:YES];
    
    self.navigationController.toolbarHidden = YES;
    self.navigationController.toolbar.hidden = YES;
    
    [self.navigationItem setPrompt:nil];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    
    [self.textFieldPw becomeFirstResponder];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.buttonCreate.layer.cornerRadius = 5.0f;
    
    PasswordGenerationParameters* params = [[PasswordGenerationParameters alloc] initWithDefaults];
    params.algorithm = kXkcd;
    params.xkcdWordCount = 4;
    params.wordSeparator = @"-";
    
    [self addShowHideToTextField:self.textFieldPw tag:100 show:YES];
    
    self.textFieldPw.text = [PasswordGenerator generatePassword:params];
    
    [self.textFieldPw addTarget:self
                           action:@selector(validateUi)
                 forControlEvents:UIControlEventEditingChanged];
    
    self.textFieldPw.delegate = self;
}

- (IBAction)onDismiss:(id)sender {
    self.onDone(NO, nil);
}

- (IBAction)onCreate:(id)sender {
    if([self passwordIsValid]) {
        self.password = self.textFieldPw.text;
        
        [AddNewSafeHelper createNewExpressDatabase:self
                                              name:self.name
                                          password:self.password
                                        completion:^(SafeMetaData * _Nonnull metadata, NSError * _Nonnull error) {
                                            if(error) {
                                                [Alerts error:self title:@"Error Creating Database" error:error completion:^{
                                                    self.onDone(NO, nil);
                                                }];
                                            }
                                            else {
                                                self.database = metadata;
                                                [self performSegueWithIdentifier:@"segueToDone" sender:nil];
                                            }
                                        }];
    }
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    if([self passwordIsValid]) {
        [textField resignFirstResponder];
        [self onCreate:nil];
    }
    
    return YES;
}

- (void)validateUi {
    BOOL enabled = [self passwordIsValid];
    self.buttonCreate.enabled = enabled;
    self.buttonCreate.backgroundColor = enabled ? UIColor.blueColor : UIColor.lightGrayColor;
}

- (BOOL)passwordIsValid {
    return self.textFieldPw.text.length;
}

- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    if([segue.identifier isEqualToString:@"segueToDone"]) {
        WelcomeCreateDoneViewController* vc = (WelcomeCreateDoneViewController*)segue.destinationViewController;
        
        vc.onDone = self.onDone;
        vc.database = self.database;
        vc.password = self.password;
    }
}

- (void)addShowHideToTextField:(UITextField*)textField tag:(NSInteger)tag show:(BOOL)show {
    // Create button
    UIButton *checkbox = [UIButton buttonWithType:UIButtonTypeCustom];
    [checkbox setFrame:CGRectMake(2 , 2, 24, 24)];  // Not sure about size
    [checkbox setTag:tag]; // hacky :(
    
    [checkbox addTarget:self action:@selector(toggleShowHidePasswordText:) forControlEvents:UIControlEventTouchUpInside];
    
    [checkbox setAccessibilityLabel:@"Show/Hide Password"];
    
    // Setup image for button
    [checkbox.imageView setContentMode:UIViewContentModeScaleAspectFit];
    [checkbox setImage:[UIImage imageNamed:@"visible"] forState:UIControlStateNormal];
    [checkbox setImage:[UIImage imageNamed:@"invisible"] forState:UIControlStateSelected];
    [checkbox setImage:[UIImage imageNamed:@"invisible"] forState:UIControlStateHighlighted];
    [checkbox setAdjustsImageWhenHighlighted:TRUE];
    checkbox.imageEdgeInsets = UIEdgeInsetsMake(0, -8, 0, 0); // Image is too close to border otherwise
                                                              //    checkbox.layer.borderColor = UIColor.redColor.CGColor;
                                                              //    checkbox.layer.borderWidth = 1;

    // Setup the right view in the text field
    [textField setClearButtonMode:UITextFieldViewModeAlways];
    [textField setRightViewMode:UITextFieldViewModeAlways];
    [textField setRightView:checkbox];
    
    // Setup Tag so the textfield can be identified
    //    [textField setTag:-1];
    
    if(show) {
        [checkbox setSelected:YES];
        textField.secureTextEntry = NO;
    }
    else {
        [checkbox setSelected:NO];
        textField.secureTextEntry = YES;
    }
}

- (void)toggleShowHidePasswordText:(UIButton*)sender {
    if(sender.selected){
        [sender setSelected:FALSE];
    } else {
        [sender setSelected:TRUE];
    }
    
    self.textFieldPw.secureTextEntry = !sender.selected;
}

@end
