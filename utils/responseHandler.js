exports.successResponse = (res, message, data = null) => {
    res.status(200).json({
      status: 'success',
      code: 200,
      message,
      data,
      errors: null,
    });
  };
  
  exports.errorResponse = (res, code, message, errors = null) => {
    res.status(code).json({
      status: 'error',
      code,
      message,
      data: null,
      errors,
    });
  };
  