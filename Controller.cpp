#include <stdio.h>
#include <iostream>
#include <limits>
#include <conio.h>
#include "Controller.h"

Controller::Controller():
	Killers(), ModeIgnore(false), ModeVerbose(false), ModeMutex(NULL)
{}
