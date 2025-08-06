const errorMiddleware = (err, req, res, next) => {
  console.error("❌ Error caught:", err);

  res.status(err.statusCode || 500).json({
    success: err.success || false,
    message: err.message || "Internal Server Error",
    errors: err.errors || [],
    data: err.data || null,
  });
};

export default errorMiddleware;
