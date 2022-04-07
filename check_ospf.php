<?php
# PNP4Nagios template: check_ospf.php

$color = array("#ff0000", "#e100ff", "#00e5ff", "#37ce37", "#ffcd00", "#fff900", "#cbff00", "#00ff00");

$ds_name[1] = "OSPF neighbors";
$opt[1] = "--lower-limit=0 --vertical-label \"neighbors\" --alt-y-grid --alt-autoscale-max";
$def[1] = "";

# define RRD variables and draw AREAs with different colors
foreach ($this->DS as $KEY=>$VAL) {
  $color_index = $KEY % sizeof($color);
  $def[1] .= "DEF:count".$KEY."=".$RRDFILE[$KEY+1].":".$DS[$KEY+1].":AVERAGE ";
  $def[1] .= "AREA:count".$KEY.$color[$color_index].":\"".$VAL["NAME"].":STACK\" ";
}

# draw invisible line at 0 so we can begin a new stack from 0
$def[1] .= "CDEF:zero=count0,0,* ";
$def[1] .= "LINE1:zero:\"\" ";

# draw black lines between AREAs
foreach ($this->DS as $KEY=>$VAL) {
  $def[1] .= "LINE1:count$KEY#000000:\"\":STACK ";
}

?>
