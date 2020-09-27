package com.nokchax.study.security.twitter;

public class TwitterConfigurer {
    // twitter filter 는 시큐리티 필터에 등록이 되어 있지 않기때문에
    // 필터의 순서를 정해 주어야 하는데, init 메소드를 통해서 자동으로 필터를 등록하게 되면 순서를 정할 수 없다 따라서
    // 상속받은후 super.init()을 호출하면 안된다.
    
    // 혹은 filter comparator 를 주입해 주어야 하는데 ..
}
