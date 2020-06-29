
<?php
pwnlib_flat(range(0, 10));
pwnlib_u32(implode(array_map(function($c) {return "\\x" . str_pad(dechex($c), 2, "0");}, range(0, 255))));
?>