<!-- debug: config.php /* <?php

/**
 * Logs output for end users if debug mode is enabled
 */
function dbg_log($line) {
	if(getenv("DEBUG")) {
		print("\n  debug: {$line}");
	}
}

/**
 * Configuration for basic test requirements
 */
class TestConfig {
	public $requirements;
	public $requirement_descriptions;

	function __construct($reqs, $descs) {
		$this->requirements = $reqs;
		$this->requirement_descriptions = $descs;
	}
}

/**
 * Configuration for application internals
 */
class AppConfig {
	public $title;
	public $secret_key;

	function __construct($title, $f) {
		$this->title = $title;
		$this->secret_key = $f;
	}
}

$test_config = new TestConfig(
	array(
		"main" => '/int\s+main\(/',
		"struct" => '/struct\s*\w*\s*\{/',
		"loop" => '/for\(/',
		"preprocessor" => '!/#/'
	),
	array(
		"main" => "Declares a main function",
		"struct" => "Declares a struct",
		"loop" => "Uses a for loop"
		// Preprocessor is handled separately
	)
);
dbg_log("Initialized test config with requirements");

/**
 * App Configuration
 */
$app_config = new AppConfig(
	"C 101 @ DUCTF 2022 Final Exam",
	"DUCTF{pr3pr0c3ssOrPoWer3dPHPpEEk1ngPuzZLe_2b842b}"
);
dbg_log("Initialized app config for [title={$app_config->title}]");

?>
*/ -->
