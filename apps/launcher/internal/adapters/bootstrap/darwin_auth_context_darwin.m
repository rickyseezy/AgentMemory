//go:build darwin && cgo

#import <LocalAuthentication/LocalAuthentication.h>

void *am_create_no_ui_authentication_context(void) {
	LAContext *context = [[LAContext alloc] init];
	if (context == nil) {
		return NULL;
	}
	context.interactionNotAllowed = YES;
	return context;
}

void am_release_authentication_context(void *pointer) {
	if (pointer == NULL) {
		return;
	}
	[(LAContext *)pointer release];
}
