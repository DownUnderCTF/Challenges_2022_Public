const errorHandler = (e) => {
    const errArr = e.message.split("\n");
    // Nsjail error
    if (errArr.length >= 18) {
        return errArr[0] + "\n" + errArr[errArr.length - 3];
    }

    return e.message;
};

module.exports = {
    errorHandler,
};