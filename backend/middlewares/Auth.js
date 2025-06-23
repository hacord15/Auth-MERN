const jwt = require('jsonwebtoken');


const ensureAuthenticated =(req,res,next)=>{
    const auth = req.headers['Authorization'];
    if(!auth){
        return res.status(403)
            .json({message:"Unauthorization , JWT token is require"});

    }
    try{
        const decoded = jwt.verify(auth,process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch(err){
        return res.status(401).json({message:"Unauthorization , JWT token wrong or expired"});
    }
}

module.exports= ensureAuthenticated;