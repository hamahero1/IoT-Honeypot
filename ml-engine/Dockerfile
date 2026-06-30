FROM python:3.10-slim

WORKDIR /app

RUN pip install --no-cache-dir numpy pandas scikit-learn joblib requests

COPY predictor.py feature_extractor.py config.json ./

ENV OMP_NUM_THREADS=1
ENV OPENBLAS_NUM_THREADS=1
ENV MKL_NUM_THREADS=1
ENV NUMEXPR_NUM_THREADS=1
ENV PYTHONUNBUFFERED=1

CMD ["python", "predictor.py"]
