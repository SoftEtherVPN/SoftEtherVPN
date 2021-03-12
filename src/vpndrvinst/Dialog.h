#ifndef DIALOG_H
#define DIALOG_H

#define MAX_MESSAGE_SIZE 1024

int ShowInformation(const char *title, const char *message, ...);
int ShowWarning(const char *title, const char *message, ...);

#endif
