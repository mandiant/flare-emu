/*
Copyright (C) 2018 FireEye, Inc.

Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-BSD-3-CLAUSE or
https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be
copied, modified, or distributed except according to those terms.

Author: James T. Bennett

compiles binary for unit tests for objc2_analyzer.py
*/

#import <Foundation/Foundation.h>

@interface SimpleClass2 : NSObject
@property (nonatomic) NSString *myVar;
- (NSString *) myVar;
- (void) func1;
@end

@implementation SimpleClass2 : NSObject
@synthesize myVar = _myVar;
- (NSString *) myVar{
    return [_myVar stringByAppendingString:@"_2"];
}
- (void) func1{
    NSLog(@"%@", [self.myVar stringByAppendingString:@"_3"]);
}

- (SimpleClass2 *) init{
    if (self = [super init]) {
        NSLog(@"SimpleClass2 initialized!");
    }
    return self;
}
@end

@interface SimpleClass : NSObject
@property NSString *myVar;
@property SimpleClass2 *sc;
- (void) func1;
- (void) func2;
+ (void) func3: (SimpleClass *) sc;
@end

@implementation SimpleClass
- (SimpleClass *) init{
    if (self = [super init]) {
        _sc = [SimpleClass2 new];
    }
    return self;
}

- (void) func1{
    NSLog(@"%@", [_myVar stringByAppendingString:@"_2"]);
}

- (void) func2{
    [_sc setMyVar:@"test"];
    [_sc func1];
}

+ (void) func3: (SimpleClass *) sc{
    NSLog(@"func3 called: %@", sc.myVar);
}
@end

int randRange(int min, int max){
    return min + arc4random_uniform((max - min + 1));
}


int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *test = @"test";
        SimpleClass *sc = [SimpleClass new];
        [sc setMyVar:test];
        NSString *test1 = [test stringByAppendingString:@"1"];
        NSString *test2 = [test stringByAppendingString:@"2"];
        NSLog(@"%@", test1);
        NSLog(@"%@", test2);
        NSString *test3 = [[sc myVar] stringByAppendingString:@"3"];
        NSLog(@"%@", test3);
        [sc func1];
        [sc func2];
        [SimpleClass func3: [SimpleClass new]];
        return 0;
    }
}
