/**
 * Edited for use on spaste.oxasploits.com by Marshall Whittaker <oxagast@oxasploits.com>
 * Idea from Matrick McCarty <patricksantos1234567@gmail.com>
 */


function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}


function choosePath(e){

  document.getElementById("myInput").focus();
  if(e.key == 'Enter'){
    printUser();
  } else if(e.keyCode == '38'){ // up arrow
    e.preventDefault();
    if(counter <= 0){
      document.getElementById("myInput").value = hist[0];
    } else{
      counter--;
      document.getElementById("myInput").value = hist[counter];
    } 
  } else if(e.keyCode == '40'){ // down arrow
    e.preventDefault();
    if(document.getElementById("myInput").value == ""){
      //do nothing
    } else if(counter == hist.length - 1){
      document.getElementById("myInput").value = "";
      counter++;
    } else if(counter > hist.length - 1){
      document.getElementById("myInput").value = "";
    } else{
      counter++;
      document.getElementById("myInput").value = hist[counter];
    }
  }
}


async function start(){

  let newLine = document.createElement("div");
  newLine.className = "spaced";
  newLine.id = "sp";

  let username = document.createElement("span");
  let col = document.createElement("span");
  let til = document.createElement("span");
  let dol = document.createElement("span");

  let tbox = document.createElement("input");
  tbox.className = "inputText";
  tbox.spellcheck = false;
  tbox.id = "myInput";
  await sleep(7700);
  username.appendChild(document.createTextNode("nobody@spaste.oxasploits.com:~$ "));
  username.className = "green-text";
  newLine.appendChild(username);

  newLine.appendChild(tbox);
  document.body.appendChild(newLine);
  document.getElementById("myInput").focus();
}


function printUser(){

  x = document.getElementById("myInput").value;

  let newLine = document.createElement("div");
  newLine.className = "spaced";

  let username = document.createElement("span");
  let col = document.createElement("span");
  let til = document.createElement("span");
  let dol = document.createElement("span");
  username.appendChild(document.createTextNode("nobody@spaste.oxasploits.com:~$ "));
  username.className = "green-text";
 newLine.appendChild(username);

  let thing = document.createElement("span");
  thing.appendChild(document.createTextNode(" " + x));
  thing.className = "green-text";
  newLine.appendChild(thing);

  document.getElementById("invisible_div").appendChild(newLine);
  let element = document.getElementById("sp");
  element.scrollIntoView();
  if(x.trim() != ""){
    hist.push(document.getElementById("myInput").value);
  }
  document.getElementById("myInput").value = "";
  counter = hist.length;

  if(x == "clear"){
    clear();
  } else if(x.toLowerCase() == "help"){
    help();
  } else if(x.toLowerCase() == ""){
    // do nothing
  } else if(x.toLowerCase().startsWith("userinfo")){
    author();
  } else if((x.toLowerCase().startsWith("sudo") || (x.toLowerCase().startsWith("su ")))){
    sudo();
  } else if((x.toLowerCase().startsWith("contacts")) || x.toLowerCase().startsWith("mail")){
    email();
  } else if(x.toLowerCase() == "cat github.txt"){
    repo();
  } else if(x.toLowerCase() == "cat"){
    cat();
  } else if(x.toLowerCase().startsWith("ls")){
    listdir();
  } else if(x.toLowerCase() == "cat usage.txt"){
    usage();
  } else if ((x.toLowerCase() == "man spaste") || (x.toLowerCase() == "man sp")) {
    mansp();
  } else if(x.toLowerCase().startsWith("man ")){
    badman();
  } else if(x.toLowerCase() == "man"){
    badman2();
  } else if((x.toLowerCase() == "ls -la") || (x.toLowerCase() == "ls -al") || (x.toLowerCase() == "ls -l") || (x.toLowerCase() == "ls --all")){
    listdir();
  } else if(x.toLowerCase() == "cat install.txt"){
    installing();
  } else if(x.toLowerCase().startsWith("alias")){
    aliassp();
  } else if(x.toLowerCase().startsWith("cat ")){
    badcat();
  } else if(x.toLowerCase().startsWith("cat ")){
    badcat();
  } else if(x.toLowerCase() == "id") {
    userid();
  } else if(x.toLowerCase() == "history"){
	history();
  }else{
    invalid();
  }
  element = document.getElementById("sp");
  element.scrollIntoView();
}

function clear(){
  let element = document.getElementById("invisible_div");
  element.innerHTML = '';
}

function help(){
  const commands = []
  commands[0] = 'help' + '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0' + 'print commands';
  commands[1] = 'clear' + '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0' + 'clear terminal';
  commands[2] = 'userinfo' + '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0' + 'about spaste\'s author';
  commands[3] = 'cat github.txt' + '\xa0\xa0\xa0\xa0\xa0\xa0' + 'furnish a link to the spaste git repository';
  commands[4] = 'cat usage.txt' + '\xa0\xa0\xa0\xa0\xa0\xa0\xa0' + 'display spaste usage help page';
  commands[5] = 'cat install.txt' + '\xa0\xa0\xa0\xa0\xa0' + 'display spaste install help page';
  commands[6] = 'contacts' + '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0' + 'author email';
  commands[7] = 'history' + '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0' + 'previously used commands';
  commands[7] = 'man spaste' + '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0' + 'spaste manual entry';
  commands[8] = 'alias sp' + '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0' + 'show shell alias to be installed';

  for(let i = 0; i < commands.length; i++){
    let buf = document.createElement("p");
    buf.textContent = commands[i];
    buf.className = "green-text";
    document.getElementById("invisible_div").appendChild(buf);
  }
}

function invalid(){
  const store = document.createElement("div");
  store.className = "green-text";

  const err = document.createElement("div");
  // print permission denied of the command name only without the arguments
  let cmdName = x.split(" ")[0];
  err.appendChild(document.createTextNode(cmdName + ": permission denied."));

  const hlp = document.createElement("div");
  hlp.appendChild(document.createTextNode("Type " + "\'help\' for the list of commands"));

  store.appendChild(err);
  store.appendChild(hlp);
  document.getElementById("invisible_div").appendChild(store);
}

function author(){
  const store = document.createElement("div");
  const par = document.createElement("p");
  par.className = "half";

  par.textContent = "Hi! I'm oxagast, author of Spaste.  I enjoy breaking code, writing security focused"
      + " applications, exploits, and gadgets.  I also enjoy gardening, working on trucks and other"
      + " mechanical things, cooking, as well as hanging with my loving girlfriend.  If you would like"
      + " to see more of my projects, visit https://oxasploits.com!";

   par.className = "green-text";
  store.appendChild(par);
  document.getElementById("invisible_div").appendChild(par);
}


function email(){
  const store = document.createElement("p");
  store.textContent = "1. ";
  const link = document.createElement("a");
  link.textContent = "oxagast@oxasploits.com";

  link.href = "mailto:oxagast@oxasploits.com";
  store.appendChild(link);
   store.className = "green-text";

  document.getElementById("invisible_div").appendChild(store);
}

function repo(){
  const store = document.createElement("p");
  store.textContent = "The spaste ";
  const link = document.createElement("a");
  link.textContent = "git repo";

  link.href = "https://github.com/oxagast/spaste";
  store.appendChild(link);
   store.className = "green-text";
  document.getElementById("invisible_div").appendChild(store);
}

function usage(){
  const store = document.createElement("div");
  const par = document.createElement("p");
  par.className = "half";

  par.textContent = "Usage: echo oxagast | sp";

  store.appendChild(par);

    par.className = "green-text";
  document.getElementById("invisible_div").appendChild(par);
}

function installing(){
  const store = document.createElement("div");
  const par = document.createElement("p");
  par.className = "half";

  par.textContent = "Install:  ./install.sh";

  store.appendChild(par);
    par.className = "green-text";
  document.getElementById("invisible_div").appendChild(par);
}

function cat() {
  const store = document.createElement("div");
  const par = document.createElement("p");
  par.className = "half";

  par.textContent = "cat: This command requies an argument!";

  store.appendChild(par);
    par.className = "green-text";
  document.getElementById("invisible_div").appendChild(par);
}

function listdir() {
  const store = document.createElement("div");
  const par = document.createElement("p");
  par.className = "half";

  par.textContent = "github.txt install.txt usage.txt";

  store.appendChild(par);
    par.className = "green-text";
  document.getElementById("invisible_div").appendChild(par);
}

function sudo() {
  const store = document.createElement("div");
  const par = document.createElement("p");
  par.className = "half";

  par.textContent = "... yeah, nice try, dickhole.";

  store.appendChild(par);
    par.className = "green-text";
  document.getElementById("invisible_div").appendChild(par);
}


function mansp() {
  const store = document.createElement("div");
  const par = document.createElement("p");
  par.className = "half";

  par.textContent = "cat /etc/passwd | timeout 3s openssl s_client -quiet -servername spaste.oxasploits.com -verify_return_error -connect spaste.oxasploits.com:8866 2>/dev/null | grep -v END | tr -d '\\n'; echo";

  store.appendChild(par);
    par.className = "green-text";
  document.getElementById("invisible_div").appendChild(par);
}

function aliassp() {
  const store = document.createElement("div");
  const par = document.createElement("p");
  par.className = "half";

  par.textContent = "sp=\"timeout 3s openssl s_client -quiet -servername spaste.oxasploits.com -verify_return_error -connect spaste.oxasploits.com:8866 2>/dev/null | grep -v END | tr -d '\\n'; echo\"";

  store.appendChild(par);
    par.className = "green-text";
  document.getElementById("invisible_div").appendChild(par);
}

function badman2() {
  const store = document.createElement("div");
  const par = document.createElement("p");
  par.className = "half";

  par.textContent = "man: This command requires and argument!"; 

  store.appendChild(par);
    par.className = "green-text";
  document.getElementById("invisible_div").appendChild(par);
}

function badman() {
  const store = document.createElement("div");
  const par = document.createElement("p");
  par.className = "half";

  par.textContent = "man: No manual entry for " + x.substring(4).trim(); 

  store.appendChild(par);
    par.className = "green-text";
  document.getElementById("invisible_div").appendChild(par);
}


function userid() {
  const store = document.createElement("div");
  const par = document.createElement("p");
  par.className = "half";

  par.textContent = "uid=1000(nobody) gid=55(nogroup) groups=5(nogroup),55(spaste)";

  store.appendChild(par);
    par.className = "green-text";
  document.getElementById("invisible_div").appendChild(par);
}




function badcat() {
  const store = document.createElement("div");
  const par = document.createElement("p");
  par.className = "half";

  par.textContent = "cat: No such file or directory!";

  store.appendChild(par);
    par.className = "green-text";
  document.getElementById("invisible_div").appendChild(par);
}


function history(){
  for(let i = 0; i < hist.length; i++){
    let buf = document.createElement("p");
    buf.textContent = hist[i];
    buf.className = "green-text";
    document.getElementById("invisible_div").appendChild(buf);
  }
}


window.addEventListener("keydown", choosePath); // listen for key presses
var x = "";			// the input that will be in the input box
var sleepTime = 30; // the time  between each color change for logo
var hist = [];		// an array to store all commands excecuted by the user
var counter = 0;	// used to sift through the previous commands
