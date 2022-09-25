<?php
if(isset($_POST['code']) && strlen($_POST['code']) > 1000) {
    http_response_code(413);
    header("Content-Type: text/plain");
    die("Payload too large");
}

require_once "config.php";


function check_requirements($code) {
    global $test_config;
    $passed = true;
    $requirements = ["main" => true, "struct" => true, "loop" => true, "preprocessor" => true];

    foreach($test_config->requirements as $key => $pattern) {
        $expected = substr($pattern, 0, 1) == '!' ? 0 : 1;
        $pattern = ltrim($pattern, '!');

        if(preg_match($pattern, $code) !== $expected) {
            $requirements[$key] = false;
            $passed = false;
        }
    }

    return [$passed, $requirements];
}

function compile($code) {
    $proc = proc_open('timeout 2s gcc -Werror -x c -o /dev/null -', [
        0 => ["pipe", "r"],
        2 => ["pipe", "w"],
    ], $pipes, null, ["PATH" => getenv("PATH")]);

    if(!is_resource($proc)) { return false; }

    try {
        fwrite($pipes[0], $code);
        fclose($pipes[0]);

        $err = stream_get_contents($pipes[2], 192);
        if(!feof($pipes[2])) { $err .= "..."; }
        fclose($pipes[2]);
    } finally {
        $rv = proc_close($proc);
    }

    return [$rv == 0, $err];
}

function build_report($requirement_results, $compile_error) {
    global $test_config;
    $report = "";

    foreach($test_config->requirement_descriptions as $key => $desc) {
        $report .= "$desc - " . ($requirement_results[$key] ? 'Passed' : 'Failed') . "\n";
    }

    $report .= "Has no preprocessor macros - " . ($requirement_results['preprocessor'] ? 'Passed' : 'Failed');
    $report .= "\nSuccessfully Compiled - " . (is_null($compile_error) ? 'Yes' : 'No');

    if(!is_null($compile_error)) {
        $report .= "\n" . $compile_error;
    }

    return $report;
}

if(isset($_POST['code'])) {
    $compile_error = null;
    [$passed, $requirements] = check_requirements($_POST['code']);
    
    if($passed) {
        [$success, $error] = compile($_POST['code']);
        if(!$success) { $compile_error = $error; }
        $passed = $passed && $success;
    }
    
    if($passed) {
        $proof = hash_hmac('sha256', $_POST['id'] ?? 'anonymous', $app_config->secret_key);
    }

    $report = build_report($requirements, $compile_error);
}
?>

<!DOCTYPE html>
<html>
    <head>
        <title>C 101 - Final Exam</title>
        <style>
            textarea {
                width: 100%;
                height: 20em;
                font-size: 1.1rem;
                background: #444;
                color: #eee;
            }
            input[type="text"] {
                background: #444;
                color: #eee;
            }
            body {
                width: 100vw;
                margin: 0;
                padding: 0;
                display: flex;
                background: #333;
                color: #ddd;
                overflow-x: hidden;
            }
            main {
                margin-left: auto;
                margin-right: auto;
            }
        </style>
    </head>
    <body>
        <main>
            <header>
                <h1><?= htmlentities($app_config->title) ?></h1>
            </header>
            <h2>Question 1</h2>
            <blockquote>
                Write a c program which correctly:
                <ul>
                    <?php foreach($test_config->requirement_descriptions as $_=>$desc) { ?>
                        <li><?= htmlentities($desc) ?></li>
                    <?php } ?>

                    <li>You may not use preprocessor macros
                        (such as <code>#include</code> or <code>#define</code>)
                        as these will interfere with our marking code</li>
                    <li>Submissions should be less than 1KB</li>
                </ul>
            </blockquote>

            <?php if(isset($_POST['code'])) { ?>
                <h3>Feedback</h3>
                <pre><?= htmlentities($report) ?></pre>
            <?php } ?>

            <?php if(isset($proof)) { ?>
            <div>You passed! Here is your completion proof: <code><?= $proof ?></code></div>
            <?php } ?>
            <form method="POST" action="/">
                <textarea name="code" required></textarea><br>
                <input type="text" name="id" placeholder="Student Id" required />
                <input type="submit" value="Submit" />
            </form>
        </main>
    </body>
</html>
