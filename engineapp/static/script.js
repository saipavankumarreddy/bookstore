// Get the modal
var modal = document.getElementById('id01');
var modal= document.getElementById('id02');
var modal= document.getElementById('id03');

// When the user clicks anywhere outside of the modal, close it
window.onclick = function(event) {
    if (event.target == modal) {
        modal.style.display = "none";
    }
}
function Validate() {
        var password = document.getElementById("psw").value;
        var confirmPassword = document.getElementById("cpsw").value;
        if (password != confirmPassword) {
            alert("Passwords do not match.");
            return false;
        }
        return true;
    }
