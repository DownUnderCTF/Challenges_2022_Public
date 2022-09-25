js-lock
=============

Opening the HTML file in a web browser, we are presented with an interface with three buttons. Looking at the JavaScript source code helps us understand what these do, and how to get the flag.

There is a `LOCK` variable, which is a large nested array of numbers. The variable `S` is used to keep track of the state of the lock and is modified whenever we press one of the buttons.

There is a `win` function which prints the flag by decrypting the hardcoded `C` data using the `sha512` hash of `S.key`. The `hit_0` and `hit_1` functions modify `S.key` and `submit_pin` will increment `S.current` by one each time if `S.T == S.current` holds. `S.T` is initially set to `LOCK` and is modified in the `hit_0` function with the assignment `S.T = S.T[S.idx]`. The `hit_1` function increments `S.idx`. When a pin is submitted, `S.idx` is reset to `0` and `S.T` is reset to `LOCK`.

We can think of the functions `hit_0` and `hit_1` as movements within the large nested `LOCK` array. `hit_1` traverses to the next element in the array, while `hit_0` traverses a level deeper into the array. Looking at the `LOCK` array, we see there are numbers from `1` to `1337` scattered among all the `0`s. To unlock each pin, we must use the `hit_0` and `hit_1` movements to traverse to the numbers `1` to `1337` in order.

We can use a simple depth first search to compute the (unique) path to each number. Concatenating these paths allows us to recover `S.key` with which the flag can be decrypted.

The following JavaScript code (written by todo#7331) can be run in the browser console to print the flag:

```js
set_status = console.log;

const path_to_key = (path) => path.map(c => '1'.repeat(c) + '0').join('');
const paths = Array(1337);

function dft(s, path=[]) {
  s.forEach((c, i) => {
    const curPath = [...path, i];
    if(typeof c === 'object') {
      dft(c, curPath);
    } else if(typeof c === 'number' && c !== 0) {
      paths[c - 1] = path_to_key(curPath);
    }
  })
}

dft(LOCK);

S.key = paths.join('');
await win();
```
