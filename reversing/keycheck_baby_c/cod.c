#include <stdio.h>
#include <string.h>

int main()
{
	char* local = {"babuzz\0"};
	char str[13];
	int index_for;
	// magic0 = \x1b\x51\x17\x2a\x1e\x4e\x3d\x10\x17\x46\x49\x14\x3d
	//	     0x1b51172a1e4e3d10174649143d
	// magic1 = \xeb\x51\xb0\x13\x85\xb9\x1c\x87\xb8\x26\x8d\x07
	char str1[] = {".Q,*.N=..FI.=\0"};
	char str2[] = {".Q.......&..\0"};
	char fin[13];
    
	for (index_for = 0;index_for < 13; index_for = index_for + 1) {
		//if ((byte)(local_80[index_for] ^ "babuzz"[(ulong)(long)index_for % 6]) != magic0[index_for])

		//printf("at turn %d, it is %c\n",index_for,index);
		str[index_for] = local[index_for % 6];
		fin[index_for] = (str[index_for] ^ str1[index_for]);
		printf("at turn %d, it is %c\n",index_for,str[index_for]^ str1[index_for]);
	}
	// local  = babuzzbabuzzb
	// local_hex = 62 61 62 75 7A 7A 62 61 62 75 7A 7A 62
	//	       \x62\x61\x62\x75\x7A\x7A\x62\x61\x62\x75\x7A\x7A\x62
	// output = L0N_T4_OL33T_
	printf("\n%s\n",str);
	printf("\n%s",fin);
	return 0;
}