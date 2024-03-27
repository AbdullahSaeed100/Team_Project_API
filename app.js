
const express=require('express');
const mongoose=require('mongoose');
const dotenv=require('dotenv');
const morgan=require('morgan');
const errorHandler =require('./controllers/errorController')
//i should move this to server.js watch environment variables section 6 for more details 
dotenv.config({path:'./config.env'})
const PORT=process.env.PORT;
mongoose.connect(process.env.MONGODB_URL).then(()=>{
    app.listen(PORT,console.log(`listening to PORT ${PORT}`))
})

const app=new express();

//if(process.env.NODE_ENV==='develpment')
    app.use(morgan('dev'));

app.use(express.json());

const routes = require('./routes/userRoutes');
app.use('/users',routes);
app.all('*',(req,res,next)=>{
    /*res.status(404).json({
        "message":`can't find ${req.originalUrl} on server`
    })*/
    const err=new Error(`can't find ${req.originalUrl} on server`);
    err.statusCode=404;
    next(err);
});

app.use(errorHandler);




module.exports=app;
