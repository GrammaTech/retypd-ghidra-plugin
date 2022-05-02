#include<math.h>


struct vec
{
    float x;
    float y;
    float z;
} typedef vec;


void foo1(vec* t, float x){
    t->x = x+0.3f;
    t->y = cosf(t->z) * x;
    return;
}

void foo2(vec* t, float x, float y) {
    t->y = x + y;
}

float foo3(vec* t, float x) {
    return t->z + x;
}

int main(){
    vec a;
    foo1(&a,0.1f);
    foo2(&a,0.2f, 0.3f);
    a.x = foo3(&a, 0.4f);
    return 0;
}
