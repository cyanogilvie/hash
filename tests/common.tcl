if {"::tcltest" ni [namespace children]} {
	package require tcltest
	namespace import ::tcltest::*
}

loadTestedCommands
package require hash

testConstraint testMode [expr {[llength [info commands ::hash::::_testmode_areion_vlif_init_state]]>0}]
