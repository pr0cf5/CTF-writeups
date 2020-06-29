
<?php

$ref_bool = true;
$ref_int = 0;
$ref_string = "a";
$ref_array = array(0);
$ref_object = new StdClass();

function templateFunction($templateParameter) {
	return 0;
}

function templateGenerator() {
	yield 0;
}

class TemplateClass {
	var $templateProperty;
	const TEMPLATE_CONSTANT = 0;
	function templateMethod() {
		return 0;
	}
}


<phpfuzz>

?>
