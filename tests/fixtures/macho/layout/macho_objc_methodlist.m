#import <Foundation/Foundation.h>

@interface ArMethodListDemo : NSObject
- (int)answer;
@end

@implementation ArMethodListDemo

- (int)answer {
    return 7;
}

@end

int main(void) {
    @autoreleasepool {
        ArMethodListDemo *demo = [[ArMethodListDemo alloc] init];
        return [demo answer];
    }
}
