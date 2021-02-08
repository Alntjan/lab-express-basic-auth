module.exports = (req, res, next) => {
  if (req.session.currentUser) {
    next();
  } else {
    res.render("auth/no-premission");
  }
};
