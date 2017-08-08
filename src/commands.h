/*  commands.h
 *
 *
 *  Copyright (C) 2014 toxbot All Rights Reserved.
 *
 *  This file is part of toxbot.
 *
 *  toxbot is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  toxbot is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with toxbot. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef COMMANDS_H
#define COMMANDS_H

#define MAX_COMMAND_LENGTH TOX_MAX_MESSAGE_LENGTH

int execute(Tox *m, int friendnumber, const char *input, int length);
void cmd_invite(Tox *m, uint32_t friendnum, int argc, char (*argv)[MAX_COMMAND_LENGTH]);

#endif    /* COMMANDS_H */
