#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "utils.h"
#include "tic.h"

static void print_field(int [3][3]);
static int valid_input(int, int, int [3][3]);
static int ended(int [3][3]);
void tictactoe(int *);

static void print_field(int field[3][3]) {
    //printf("\n");
    puts("");
    for (int i = 0; i < 3; i++) {
        printf("%d", 3 - i);
        for (int j = 0; j < 3; j++) {
            if (field[i][j] == 0) {
                printf("  ");
            } else if (field[i][j] == 1) {
                printf(" O");
            } else if (field[i][j] == 2) {
                printf(" X");
            } else {
                printf(" %d", field[i][j]);
            }
        }
        //printf("\n");
        puts("");
    }
    //printf("  1 2 3\n\n");
    puts("\x0b\x0b\x1a\x0b\x19\x0b\x18\x21");
}

static int valid_input(int one, int two, int field[3][3]) {
    if (one < 0 || one > 2 || two < 0 || one > 2) {
        // invalid numbers
        return -1;
    }

    if (field[two][one] != 0) {
        // invalid number
        return -1;
    }
    return 0;
}

static int ended(int field[3][3]) {
    int twoLongerIdx = 1;
    int twoLonger[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int tmpC2;
    int countC2;
    int tmpR2;
    int countR2;

    int tmpC;
    int countC;
    int tmpR;
    int countR;
    int tmpD1 = field[0][0];
    int countD1 = 0;
    int tmpD2 = field[2][0];
    int countD2 = 0;
    for (int i = 0; i < 3; i++) {
        tmpC2 = field[i][2];
        countC2 = 0;
        tmpR2 = field[2][i];
        countR2 = 0;

        tmpC = field[i][0];
        countC = 0;
        tmpR = field[0][i];
        countR = 0;
        for (int j = 0; j < 3; j++) {
            if (field[i][j] == tmpC) {
                countC++;
            }
            if (field[j][i] == tmpR) {
                countR++;
            }

            if (field[i][2 - j] == tmpC2)
                countC2++;
            if (field[2 - j][i] == tmpR2)
                countR2++;
        }

        if (countC >= 3) {
            if (tmpC != 0) {
                return tmpC;
            }
        } else if (countC == 2) {
            if (tmpC != 0) {
                if (field[i][1] == 0 || field[i][2] == 0) {
                    twoLonger[twoLongerIdx] = 10 + i;
                    twoLongerIdx++;
                }
            }
        }

        if (countR >= 3) {
            if (tmpR != 0) {
                return tmpR;
            }
        } else if (countR == 2) {
            if (tmpR != 0) {
                if (field[1][i] == 0 || field[2][i] == 0) {
                    twoLonger[twoLongerIdx] = 20 + i;
                    twoLongerIdx++;
                }
            }
        }

        if (field[i][i] == tmpD1) {
            countD1++;
        }
        if (field[i][2 - i] == tmpD2) {
            countD2++;
        }

        if (countC2 == 2) {
            if (tmpC2 != 0) {
                if (field[i][0] == 0 || field[i][1] == 0) {
                    twoLonger[twoLongerIdx] = 10 + i;
                    twoLongerIdx++;
                }
            }
        } else if (countR2 == 2) {
            if (tmpR2 != 0) {
                if (field[0][i] == 0 || field[1][i] == 0) {
                    twoLonger[twoLongerIdx] = 20 + i;
                    twoLongerIdx++;
                }
            }
        }
    }
    if (countD1 >= 3) {
        if (tmpD1 != 0) {
            return tmpD1;
        }
    }
    if (countD2 >= 3) {
        if (tmpD2 != 0) {
            return tmpD2;
        }
    }

    if (twoLongerIdx == 1) {
        return 0;
    }
    if (rand() % (twoLongerIdx + 5) == 3)
        return 0;
    return twoLonger[rand() % (twoLongerIdx)];
}

void tictactoe(int *ret) {
    int field[3][3] = {{0, 0, 0}, {0, 0, 0}, {0, 0, 0}};
    int winner = 0;
    srand(time(NULL));

    // 0 nix
    // 1 O
    // 2 X

    print_field(field);

    for (int i = 0; i < 9; i++) {
        if (i % 2 == 1) {
            if (winner >= 10 && winner < 20) {
                // column
                // field[winner-10][random]
                int one = rand() % 3;
                while (valid_input(one, winner - 10, field)) {
                    one = rand() % 3;
                }
                field[winner - 10][one] = (i % 2) + 1;
            } else if (winner >= 20 && winner < 30) {
                // row
                // field[winner-20][random]
                int one = rand() % 3;
                while (valid_input(winner - 20, one, field)) {
                    one = rand() % 3;
                }
                field[one][winner - 20] = (i % 2) + 1;
            } else if (winner >= 30 && winner < 40) {
                // d1
                // field[random][random]
                int one = rand() % 3;
                while (valid_input(one, one, field)) {
                    one = rand() % 3;
                }
                field[one][one] = (i % 2) + 1;
            } else if (winner >= 40 && winner < 50) {
                // d2
                // field[2-random][random]
                int one = rand() % 3;
                while (valid_input(2 - one, one, field)) {
                    one = rand() % 3;
                }
                field[one][2 - one] = (i % 2) + 1;
            } else if (!valid_input(1, 1, field)) {
                field[1][1] = (i % 2) + 1;
            } else {
                int one = rand() % 3;
                int two = rand() % 3;
                while (valid_input(one, two, field)) {
                    one = rand() % 3;
                    two = rand() % 3;
                }
                field[two][one] = (i % 2) + 1;
            }
            print_field(field);
        } else {
            char input[4];
            printf("player%d:\n", (i % 2) + 1);
            puts("\x42\x45\x5b\x5e\x5f\x0b\x5f\x5c\x44\x0b\x45\x5e\x46\x49\x4e\x59\x58\x0b\x59\x4a\x45\x4c\x42\x45\x4c\x0b\x4d\x59\x44\x46\x0b\x1a\x0b\x5f\x44\x0b\x18\x0b\x70\x4e\x4c\x05\x0b\x1a\x19\x76");
            read_input(input, 4);
            //read_input("input two numbers ranging from 1 to 3 [eg. 12]\n", input, 4);
            if(feof(stdin)) {
                return;
            }
            if (strlen(input) < 2) {
                i--;
                //printf("invalid input\n\n");
                puts("\x42\x45\x5d\x4a\x47\x42\x4f\x0b\x42\x45\x5b\x5e\x5f");
                continue;
            }

            int one = input[0] - 49;
            int two = 2 - (input[1] - 49);

            if (valid_input(one, two, field)) {
                i--;
                //printf("invalid input\n\n");
                puts("\x42\x45\x5d\x4a\x47\x42\x4f\x0b\x42\x45\x5b\x5e\x5f");
                continue;
            }

            field[two][one] = (i % 2) + 1;
        }

        winner = ended(field);
        if (winner > 0 && winner < 10) {
            // print_field(field);
            break;
        }
    }
    if (winner == 1) {
        print_field(field);
        //printf("congrats you won!\n");
        puts("\x48\x44\x45\x4c\x59\x4a\x5f\x58\x0b\x52\x44\x5e\x0b\x5c\x44\x45\x0a");
        *ret = 1;
    } else if (winner == 2) {
        //printf("you lost\n");
        puts("\x52\x44\x5e\x0b\x47\x44\x58\x5f");
        *ret = -1;
    } else {
        print_field(field);
        //printf("no one won\n");
        puts("\x45\x44\x0b\x44\x45\x4e\x0b\x5c\x44\x45");
        *ret = 0;
    }
}
