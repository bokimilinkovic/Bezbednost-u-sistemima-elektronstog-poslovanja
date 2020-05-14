<template>
    <body>
    <nav class="navbar navbar-dark bg-dark">
        <a class="navbar-brand" href="/createnew">Create New</a>
        <a class="navbar-brand" href="/home">Visit All</a>
    </nav>
    <br>
    <br>
    <h2>Create new certificate</h2>
    <div  style=" background-color: #3CBC8D">
        <form method="post" enctype="multipart/form-data" action="http://localhost:8080/create">
            <div class="form-row">
                <div class="form-group col-md-6">
                    <label>Country</label>
                    <input type="text" v-model="country" class="form-control" id="country" name="country" placeholder="Country">
                </div>
                <div class="form-group col-md-6">
                    <label>Organization</label>
                    <input type="text" class="form-control" v-model="organization" id="organization" name="organization" placeholder="Organization">
                </div>
            </div>
            <div class="form-group col-md-4">
                <label for="inputAddress">Address</label>
                <input type="text" class="form-control" v-model="address" id="inputAddress" name="streetaddress" placeholder="1234 Main St">
            </div>
            <div class="form-group col-md-4">
                <label for="inputAddress2">Province</label>
                <input type="text" class="form-control" id="inputAddress2" v-model="province" name="province" placeholder="Province">
            </div>
            <div class="form-group col-md-4">
                <label for="inputEmail4">Email</label>
                <input type="email" class="form-control" v-model="email" name="emailaddress" id="inputEmail4" placeholder="enter@email.com">
            </div>

            <div class="form-group col-md-2">
                    <label for="inputCity">Locality</label>
                    <input type="text" class="form-control" v-model="locality" name="locality" id="inputCity">
            </div>
            <div class="form-group col-md-2">
                    <label for="inputZip">Serial Number</label>
                    <input type="text" name ="serialnumber" v-model="serialnum" class="form-control" id="inputSerialNumber">
            </div>
            <div class="form-group col-md-2">
                    <label for="inputZip">Postal Code(zip)</label>
                    <input type="text" class="form-control" id="inputZip" v-model="postal" name="postalcode" placeholder="15 000">
            </div>
            <div class="form-group col-md-3">
                   <label>Valid from</label>
                    <input type="date" id="validform" v-model="validfrom" name="startsat">
            </div>
            <div class="form-group col-md-3">
                    <label width="20px">Valid To</label>
                    <input type="date" id="validto" v-model="validto" name="endsat">
            </div>

            <div>
                <div form-group col-md-4>
                <div class="form-check">
                    <input class="form-check-input" v-model="ca" name="certificateauthority" type="checkbox" id="gridCheck">
                    <label class="form-check-label" for="gridCheck">
                        Certificate authority
                    </label>
                </div>
                </div>
                <h3>Choose issuer</h3>
                <div class="form-group col-md-4">
                    <select id="inputState" class="form-control" name="issuer">
                        <option selected>root - self signed</option>
                        <v-for="cert in certificats">
                            <option>{{$value}}</option>
                        {{end}}
                    </select>
                </div>
                <div class="form-group col-md-4">
                    <label>Password...</label>
                    <input type="password">
                </div>
            </div>
            <br>
            <div>
                <div class="form-group col-md-4">
                    <label>Domain</label>
                    <input type="text"  class="form-control" id="domain" name="commonName">
                </div>
            </div>
            <button type="submit" class="btn btn-primary">Create certificate</button>
        </form>
    </div>
    <script>
        var x = document.getElementById("inputSerialNumber");
        x.value = Math.floor((Math.random() * 1000) + 1).toString()
    </script>
</body>
</template>
<script>
import axios from 'axios'
export default {
    name: 'NewCertificate',
    data(){
        return {
            country: '',
            organization: '',
            address: '',
            province: '',
            email: '',
            locality: '',
            serialnum: '',
            postal: '',
            validfrom: '',
            validto: '',
            ca: '',
            


        }
    }
}
</script>