const pool=require('../config/db') ;
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken') ;

const register =async(req,res,next)=>{
    try{
    const {username ,email,password} =req.body ;
    const userExists =await pool.query(
        'SELECT * FROM users WHERE email = $1 OR username = $2',
         [email, username]


    );
    if(userExists.rows.length>0){
        return res.status(400).json({message:"l'utilisiteur déja existant"});
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const  newUser =await pool.query(
        'INSERT INTO users (username ,email, password_hash) VALUES ($1,$2,$3) RETURNING *' ,
        [username,email,hashedPassword]  
    )

    const token =generateToken(newUser.rows[0].id) ;

    res.status(201).json({
        id: newUser.rows[0].id,
        username: newUser.rows[0].username,
        email: newUser.rows[0].email,
        token 

    });
    
    

}catch(error){
    next(error) ;

}
}

const login =async (req,res,next)=>{
    try{
        const {email,password}=req.body;
        const  user = await pool.query(
            'SELECT * FROM users WHERE email=$1',
            [email]

        )
        if(user.rows.length ==0){
            return res.status(401).json({message :'INVALID CREDENTIALS'}) ;
        }

        const isMatch =await bcrypt.compare(password,user.rows[0].password_hash) ;

        if(!isMatch){
            return res.status(401).json({message :'INVALID CREDENTIALS'})
        }

        const token = generateToken(user.rows[0].id) ;

        res.status(201).json({
            id: user.rows[0].id,
            username: user.rows[0].username,
            email: user.rows[0].email,
            token


        });


    }catch(error){
        next(error) ;
    }
            
        

    
    

};

const getMe = async (req, res, next) =>{
  try {
    const user = await pool.query(
      'SELECT id, username, email FROM users WHERE id = $1',
      [req.user.id]
    );
    
    res.status(200).json(user.rows[0]);
  } catch (error) {
    next(error);
  }
};

const generateToken = (id) =>{
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

module.exports = {
  register,
  login,
  getMe
};


   